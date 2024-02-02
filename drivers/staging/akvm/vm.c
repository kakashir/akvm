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

	WARN_ON(!xa_empty(&vm->vcpus));
	xa_destroy(&vm->vcpus);

	WARN_ON(!ida_is_empty(&vm->vcpu_index_pool));
	ida_destroy(&vm->vcpu_index_pool);
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
	switch(ioctl) {
	case AKVM_CREATE_VCPU:
		return akvm_vm_ioctl_create_vcpu(f);
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
};

static int akvm_init_vm(struct vm_context *vm)
{
	ida_init(&vm->vcpu_index_pool);
	mutex_init(&vm->lock);
	xa_init(&vm->vcpus);

	vm->vcpu_create_cb = akvm_vcpu_create_callback;
	vm->vcpu_destroy_cb = akvm_vcpu_destroy_callback;

	return 0;
}

int akvm_create_vm(struct file *dev)
{
	int r;
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
		goto failed_free;

	file = anon_inode_getfile("akvm-vm", &akvm_vm_ops,  vm, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(r);
		r = PTR_ERR(file);
		goto failed_free;
	}

	if (dev)
		vm->dev = get_file(dev);

	fd_install(r, file);
	pr_info("install fd:%d\n", r);
	return r;

failed_free:
	kfree(vm);
	return r;
}
