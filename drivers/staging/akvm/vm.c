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


static int akvm_vm_open(struct inode *inode, struct file *file)
{
	pr_info("%s\n", __func__);
	return 0;
}

static int akvm_vm_release(struct inode *inode, struct file *file)
{
	struct vm_context *vm = file->private_data;

	pr_info("%s\n", __func__);
	if (vm->dev)
		fput(vm->dev);
	kfree(vm);

	return 0;
}

static int akvm_vm_ioctl_create_vcpu(struct file *f)
{
	int r;
	struct vcpu_context *vcpu;

	vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL_ACCOUNT);
	if (!vcpu)
		return -ENOMEM;

	r = alloc_vmcs(vcpu);
	if (r)
		goto free_vcpu;

	prepare_vmcs(vcpu->vmcs.vmcs,
		     vmx_region_size(&vmx_capability),
		     vmx_vmcs_revision(&vmx_capability));

	vcpu_load(vcpu);

	r = setup_vmcs_control(vcpu, &vmx_capability);
	if (r)
		goto free_vcpu;

	vcpu_put(vcpu, false);

	r = akvm_create_vcpu_fd(vcpu, f);
	if (r < 0)
		goto free_vcpu;

	return r;
free_vcpu:
	kfree(vcpu);
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

int akvm_create_vm_fd(struct vm_context *vm, struct file *dev)
{
	int fd;
	struct file *file;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;

	file = anon_inode_getfile("akvm-vm", &akvm_vm_ops,  vm, O_RDWR);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	if (dev)
		vm->dev = get_file(dev);

	fd_install(fd, file);
	pr_info("install fd:%d\n", fd);
	return fd;
}
