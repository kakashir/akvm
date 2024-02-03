#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/anon_inodes.h>

#include <uapi/linux/akvm.h>

#include <asm/msr-index.h>
#include <asm/cpu_entry_area.h>
#include <asm/idtentry.h>

#include "common.h"
#include "vm.h"
#include "vcpu.h"

static int akvm_vm_alloc_vcpu_index(struct vm_context *vm)
{
	return ida_alloc_range(&vm->vcpu_index_pool,
			       0, AKVM_MAX_VCPU_NUM - 1,
			       GFP_KERNEL_ACCOUNT);
}

static void akvm_vm_free_vcpu_index(struct vm_context *vm, int index)
{
	ida_free(&vm->vcpu_index_pool, index);
}

static void akvm_vcpu_destroy_callback(struct vm_context *vm, int vcpu_index)
{
	xa_erase(&vm->vcpus, vcpu_index);
	akvm_vm_free_vcpu_index(vm, vcpu_index);
}

static int akvm_vcpu_create_callback(struct vm_context *vm, int vcpu_index,
				     struct vcpu_context *vcpu)
{
	int r;

	r = xa_err(xa_store(&vm->vcpus, vcpu_index, vcpu, GFP_KERNEL));
	return r;
}

static void akvm_vm_destroy_memory_space(struct vm_memory_space *memory)
{
	struct vm_memory_slot *slot;
	struct vm_memory_slot *tmp;

	if (!memory)
		return;

	list_for_each_entry_safe(slot, tmp, &memory->slot_list, entry) {
		list_del(&slot->entry);
		for (int i = 0; i < VM_MEM_ROOT_NUM; ++i)
			interval_tree_remove(&slot->node[i], &memory->root[i]);
		kfree(slot);
	}

	kfree(memory);
}

static int akvm_vm_create_memory_space(struct vm_memory_space **memory)
{
	struct vm_memory_space *new_memory;

	new_memory = kzalloc(sizeof(*new_memory), GFP_KERNEL_ACCOUNT);
	if (!new_memory)
		return -ENOMEM;

	for (int i = 0; i < VM_MEM_ROOT_NUM; ++i)
		new_memory->root[i] = RB_ROOT_CACHED;

	INIT_LIST_HEAD(&new_memory->slot_list);
	*memory = new_memory;
	return 0;
}

static void akvm_deinit_vm(struct vm_context *vm)
{
	WARN_ON(!xa_empty(&vm->vcpus));
	xa_destroy(&vm->vcpus);

	WARN_ON(!ida_is_empty(&vm->vcpu_index_pool));
	ida_destroy(&vm->vcpu_index_pool);

	/* free_page takes care NULL ptr */
	free_page(vm->ept_root);
	cleanup_srcu_struct(&vm->srcu);

	akvm_vm_destroy_memory_space(vm->memory);
}

static bool akvm_vm_check_memory_slot_overlap(struct vm_memory_space *memory,
					      struct vm_memory_slot *slot,
					      bool match_exact)
{
	struct interval_tree_node *search;
	struct rb_root_cached *root;
	struct vm_memory_slot *found;
	unsigned long start;
	unsigned long last;

	root = &memory->root[VM_MEM_ROOT_GPA];
	start = slot->gpa;
	last = slot->gpa + slot->size - 1;

	for (search = interval_tree_iter_first(root, start, last); search;
	     search = interval_tree_iter_next(search, start, last)) {
		if (!match_exact)
			return true;

		found = container_of(search, struct vm_memory_slot,
				     node[VM_MEM_ROOT_GPA]);
		if (slot->gpa != found->gpa)
			return false;
		if (slot->size != found->size)
			return false;
		return true;
	}

	return false;
}

#define akvm_vm_copy_memory_slot(to, from) \
{					  \
	(to)->hva = (from)->hva;	  \
	(to)->gpa = (from)->gpa;	  \
	(to)->size = (from)->size;	  \
	(to)->flags = (from)->flags;	  \
}

static int akvm_vm_init_memory_slot(struct vm_memory_slot *slot,
				    struct akvm_memory_slot __user *u_slot)
{
	struct akvm_memory_slot k_slot;

	if (copy_from_user(&k_slot, u_slot, sizeof(k_slot)))
		return -EFAULT;

	akvm_vm_copy_memory_slot(slot, &k_slot);
	return 0;
}

static int akvm_vm_insert_memory_slot(struct vm_memory_space *memory,
				      struct vm_memory_slot *slot)
{
	struct vm_memory_slot *new_slot;

	new_slot = kzalloc(sizeof(*new_slot), GFP_KERNEL_ACCOUNT);
	if (!new_slot)
		return -ENOMEM;

	akvm_vm_copy_memory_slot(new_slot, slot);
	memset(new_slot->node, 0, sizeof(new_slot->node));
	INIT_LIST_HEAD(&new_slot->entry);

	new_slot->node[VM_MEM_ROOT_HVA].start = new_slot->hva;
	new_slot->node[VM_MEM_ROOT_HVA].last =
		new_slot->hva + new_slot->size - 1;
	interval_tree_insert(&new_slot->node[VM_MEM_ROOT_HVA],
			     &memory->root[VM_MEM_ROOT_HVA]);

	new_slot->node[VM_MEM_ROOT_GPA].start = new_slot->gpa;
	new_slot->node[VM_MEM_ROOT_GPA].last =
		new_slot->gpa + new_slot->size - 1;
	interval_tree_insert(&new_slot->node[VM_MEM_ROOT_GPA],
			     &memory->root[VM_MEM_ROOT_GPA]);

	list_add(&new_slot->entry, &memory->slot_list);

	return 0;
}

static int akvm_vm_update_memory_space(struct vm_context *vm,
				       struct vm_memory_slot *new_slot,
				       bool del)
{
	struct vm_memory_space *old = vm->memory;
	struct vm_memory_space *new;
	struct vm_memory_slot *cur;
	struct vm_memory_slot *tmp;
	int r;

	/* duplicate the original memory space */
	r = akvm_vm_create_memory_space(&new);
	if (r)
		return r;

	list_for_each_entry_safe(cur, tmp, &old->slot_list, entry) {
		if (del && new_slot->gpa == cur->gpa &&
		    new_slot->size == cur->size)
				continue;
		r = akvm_vm_insert_memory_slot(new, cur);
		if (r)
			goto failed_free;
	}

	if (!del) {
		r = akvm_vm_insert_memory_slot(new, new_slot);
		if (r)
			goto failed_free;
	}
	rcu_assign_pointer(vm->memory, new);
	synchronize_srcu(&vm->srcu);
	akvm_vm_destroy_memory_space(old);

	return r;

 failed_free:
	akvm_vm_destroy_memory_space(new);
	return r;
}

static int akvm_vm_ioctl_add_memory_slot(struct vm_context *vm,
					 struct akvm_memory_slot __user *u_slot)
{
	int r;
	struct vm_memory_slot slot;

	r = akvm_vm_init_memory_slot(&slot, u_slot);
	if (r)
		return r;

	if (!IS_ALIGNED(slot.gpa, AKVM_MEMORY_SLOT_ALIGN))
		return -EINVAL;

	if (!IS_ALIGNED(slot.size, AKVM_MEMORY_SLOT_ALIGN))
		return -EINVAL;

	if (slot.flags)
		return -EINVAL;

	mutex_lock(&vm->lock);

	if (!vm->memory) {
		/* fisrt slot, just insert */
		r = akvm_vm_create_memory_space(&vm->memory);
		if (!r)
			r = akvm_vm_insert_memory_slot(vm->memory, &slot);
	} else {
		r = -EINVAL;
		if (!akvm_vm_check_memory_slot_overlap(vm->memory, &slot, false))
			r = akvm_vm_update_memory_space(vm, &slot, false);
	}

	mutex_unlock(&vm->lock);
	return r;
}


static int akvm_vm_open(struct inode *inode, struct file *file)
{
	pr_info("%s\n", __func__);
	return 0;
}

static int akvm_vm_release(struct inode *inode, struct file *file)
{
	struct vm_context *vm = file->private_data;
	struct file *dev_file = vm->dev;

	pr_info("%s\n", __func__);

	akvm_deinit_vm(vm);
	kfree(vm);

	if (dev_file)
		fput(dev_file);

	return 0;
}

static int akvm_vm_ioctl_create_vcpu(struct file *f)
{
	int r;
	struct vm_context *vm = f->private_data;

	r = akvm_vm_alloc_vcpu_index(vm);
	if (r < 0)
		return r;

	r = akvm_create_vcpu(f, vm, r);
	return r;
}

static long akvm_vm_ioctl(struct file *f, unsigned int ioctl,
			  unsigned long param)
{
	struct vm_context *vm = f->private_data;

	if (!vm)
		return -EINVAL;

	switch(ioctl) {
	case AKVM_CREATE_VCPU:
		return akvm_vm_ioctl_create_vcpu(f);
	case AKVM_MEMORY_SLOT_ADD:
		return akvm_vm_ioctl_add_memory_slot(vm, (void*)param);
	default:
		return -EINVAL;
	}

	return 0;
}

static struct file_operations akvm_vm_ops = {
	.open = akvm_vm_open,
	.unlocked_ioctl = akvm_vm_ioctl,
	.llseek = noop_llseek,
	.release = akvm_vm_release,
	.owner = THIS_MODULE,
};

static int akvm_init_vm(struct vm_context *vm)
{
	vm->ept_root = __get_free_page(GFP_KERNEL_ACCOUNT);
	if (!vm->ept_root)
		return -ENOMEM;

	ida_init(&vm->vcpu_index_pool);
	mutex_init(&vm->lock);
	xa_init(&vm->vcpus);
	init_srcu_struct(&vm->srcu);

	vm->vcpu_create_cb = akvm_vcpu_create_callback;
	vm->vcpu_destroy_cb = akvm_vcpu_destroy_callback;

	return 0;
}

int akvm_create_vm(struct file *dev)
{
	int r;
	int fd;
	struct vm_context *vm;
	struct file *file;

	vm = kzalloc(sizeof(*vm),GFP_KERNEL_ACCOUNT);
	if (!vm)
		return -ENOMEM;

	r = akvm_init_vm(vm);
	if (r)
		goto failed_free;

	r = get_unused_fd_flags(O_CLOEXEC);
	if (r < 0)
		goto failed_deinit;
	fd = r;

	file = anon_inode_getfile("akvm-vm", &akvm_vm_ops,  vm, O_RDWR);
	if (IS_ERR(file)) {
		r = PTR_ERR(file);
		goto failed_putfd;
	}

	if (dev)
		vm->dev = get_file(dev);

	fd_install(fd, file);
	pr_info("install fd:%d\n", fd);
	return fd;

failed_putfd:
	put_unused_fd(fd);
failed_deinit:
	akvm_deinit_vm(vm);
failed_free:
	kfree(vm);
	return r;
}
