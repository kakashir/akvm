#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/topology.h>

#include <uapi/linux/akvm.h>

#include <asm/msr-index.h>
#include <asm/cpu_entry_area.h>
#include <asm/idtentry.h>

#include "common.h"
#include "x86.h"
#include "vmx.h"
#include "vm.h"
#include "vcpu.h"

#ifdef _DEBUG
#define akvm_pr_info pr_info
#else
#define akvm_pr_info(...)
#endif

static long usage_count;
static DEFINE_MUTEX(usage_count_lock);

struct preempt_ops akvm_preempt_ops;

DEFINE_PER_CPU(struct vmx_region *, vmx_region);
DEFINE_PER_CPU(struct vmcs_list, vmcs_list);

struct vmx_capability vmx_capability;

static void free_vmx_region(void)
{
	int cpu;
	struct vmx_region *region;

	/* kfree takes care NULL ptr */
	for_each_possible_cpu(cpu) {
		region = per_cpu(vmx_region, cpu);
		per_cpu(vmx_region, cpu) = NULL;
		kfree(region);
	}
}

static int alloc_vmx_region(size_t size)
{
	int cpu;
	struct vmx_region *region;

	for_each_possible_cpu(cpu) {
		WARN_ON(per_cpu(vmx_region, cpu));
		region = kmalloc_node(size, GFP_KERNEL_ACCOUNT,
				      cpu_to_node(cpu));
		if (!region) {
			pr_err("failed to alloc vmxon region for cpu %d\n", cpu);
			goto failed_free;
		}
		per_cpu(vmx_region, cpu) = region;
	}
	return 0;

 failed_free:
	free_vmx_region();
	return -ENOMEM;
}

static void vmx_basic_info_checker(void *info)
{
	int r;
	atomic_t *ret = info;
	struct vmx_capability cap;

	r = probe_vmx_basic_info(&cap);
	if (r) {
		atomic_inc(ret);
		return;
	}

	if (memcmp(&cap, &vmx_capability, sizeof(cap)))
		atomic_inc(ret);
}

static int check_vmx_basic_info(void)
{
	atomic_t r = ATOMIC_INIT(0);

	on_each_cpu(vmx_basic_info_checker, &r, 1);

	if (atomic_read(&r))
		return -EFAULT;
	return 0;
}

static void vmx_on_cpu(void *info)
{
	atomic_t *r = info;
	struct vmx_region *region = this_cpu_read(vmx_region);

	prepare_vmx_region(region,
			   vmx_region_size(&vmx_capability),
			   vmx_vmcs_revision(&vmx_capability));
	if (vmx_on(region))
		atomic_inc(r);
}

static void vmx_off_cpu(void *info)
{
	struct vmx_region *region = this_cpu_read(vmx_region);

	if (region)
		vmx_off();
}

static int vmx_on_all(void)
{
	atomic_t r = ATOMIC_INIT(0);

	on_each_cpu(vmx_on_cpu, &r, 1);

	if (atomic_read(&r))
		return -EFAULT;
	return 0;
}

static void vmx_off_all(void)
{
	on_each_cpu(vmx_off_cpu, NULL, 1);
}


static int akvm_hardware_enable(void)
{
	int r = 0;

	mutex_lock(&usage_count_lock);

	if (++usage_count == 1) {
		r = check_vmx_basic_info();
		if (r) {
			pr_err("check_vmx_basic_info() failed\n");
			goto exit;
		}

		r = alloc_vmx_region(vmx_region_size(&vmx_capability));
		if (r) {
			pr_err("failed to alloc vmx region\n");
			goto exit;
		}
		r = vmx_on_all();
	}
 exit:
	mutex_unlock(&usage_count_lock);
	return r;
}

static void akvm_hardware_disable(void)
{
	mutex_lock(&usage_count_lock);

	if (--usage_count == 0) {
		vmx_off_all();
		free_vmx_region();
	}

	mutex_unlock(&usage_count_lock);
}


static int akvm_ioctl_get_vmx_info(struct file *f, unsigned long param)
{
	struct akvm_vmx_info vmx_info;

	vmx_info.vmx_basic_msr = vmx_capability.msr_vmx_basic;
	vmx_info.vmx_misc_msr = vmx_capability.msr_vmx_misc;
	vmx_info.vmx_ept_vpid_msr = vmx_capability.msr_ept_vpid;

	if (copy_to_user((void __user*)param, &vmx_info, sizeof(vmx_info)))
		return -EFAULT;

	return 0;
}

static int akvm_ioctl_create_vm(struct file *f)
{
	int r;
	struct vm_context *vm;

	vm = kzalloc(sizeof(*vm), GFP_KERNEL_ACCOUNT);
	if (!vm)
		return -ENOMEM;

	r = akvm_create_vm_fd(vm, f);
	if (r < 0)
		goto failed_free;

	return r;

 failed_free:
	kfree(vm);
	return r;
}

static int akvm_dev_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;

	return akvm_hardware_enable();
}

static int akvm_dev_release(struct inode *inode, struct file *file)
{
	pr_info("%s\n", __func__);
	akvm_hardware_disable();
	return 0;
}

static long akvm_dev_ioctl(struct file *f, unsigned int ioctl,
			   unsigned long param)
{
	int r;

	switch(ioctl) {
	case AKVM_CREATE_VM:
		r = akvm_ioctl_create_vm(f);
		break;
	case AKVM_GET_VMX_INFO:
		r = akvm_ioctl_get_vmx_info(f, param);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static void akvm_sched_in(struct preempt_notifier *pn, int cpu)
{
	akvm_vcpu_sched_in(pn, cpu);
}

static void akvm_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	akvm_vcpu_sched_out(pn, next);
}

static struct file_operations akvm_dev_ops = {
	.open = akvm_dev_open,
	.unlocked_ioctl = akvm_dev_ioctl,
	.llseek = noop_llseek,
	.release = akvm_dev_release,
};

static struct miscdevice akvm_dev = {
	MISC_DYNAMIC_MINOR,
	"akvm",
	&akvm_dev_ops,
};

static int do_akvm_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		INIT_LIST_HEAD(&per_cpu(vmcs_list, cpu).head);

	preempt_notifier_inc();
	akvm_preempt_ops.sched_in = akvm_sched_in;
	akvm_preempt_ops.sched_out = akvm_sched_out;

	return 0;
}

static int __init akvm_init(void)
{
	int r;

	r = do_akvm_init();
	if (r) {
		pr_err("akvm: failed to init akvm:%d\n", r);
		goto exit;
	}

	r = probe_vmx_basic_info(&vmx_capability);
	if (r) {
		pr_err("akvm: failed to probe VMX basic information\n");
		goto exit;
	}

	r = misc_register(&akvm_dev);
	if (r)
		pr_err("akvm: failed to register device\n");

 exit:
	return r;
}

static void do_akvm_exit(void)
{
	int cpu;

	preempt_notifier_dec();

	for_each_possible_cpu(cpu)
		WARN_ON(!list_empty(&per_cpu(vmcs_list, cpu).head));

}

static void __exit akvm_exit(void)
{
	misc_deregister(&akvm_dev);
	do_akvm_exit();
}

module_init(akvm_init);
module_exit(akvm_exit);
MODULE_LICENSE("GPL");
