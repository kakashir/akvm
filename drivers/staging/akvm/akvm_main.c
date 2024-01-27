#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

#include <uapi/linux/akvm.h>

#include <asm/msr-index.h>
#include <asm/vmx.h>

#include "common.h"

#define VMCS_MEM_TYPE_UC 0
#define VMCS_MEM_TYPE_WB 6

static struct vmx_capability vmx_capability;

static void vmx_get_ctl_msr_fix_bit(int msr, u32 *ctl_fix_0, u32 *ctl_fix_1)
{
	u32 low, high;

	rdmsr(msr, low, high);

	*ctl_fix_0 = ~high;
	*ctl_fix_1 = low;
}

static void vmx_get_ctl_msr_fix_bit2(int msr, u32 *ctl_fix_0, u32 *ctl_fix_1)
{
	u64 val;

	rdmsrl(msr, val);

	*ctl_fix_0 = ~val;
	*ctl_fix_1 = 0;
}

static void vmx_get_cr_fix_bit(int msr_fixed0, int msr_fixed1,
			       u64* cr_fixed0, u64 *cr_fixed1)
{
	u64 val;

	rdmsrl(msr_fixed0, val);
	*cr_fixed1 = val;

	rdmsrl(msr_fixed1, val);
	*cr_fixed0 = ~val;
}



static int probe_vmx_basic_info(struct vmx_capability *info)
{
	u32 proc_based_allowed_1;

	rdmsrl(MSR_IA32_VMX_BASIC, info->msr_vmx_basic);
	rdmsrl(MSR_IA32_VMX_MISC, info->msr_vmx_misc);
	rdmsrl(MSR_IA32_VMX_EPT_VPID_CAP, info->msr_ept_vpid);

	vmx_get_ctl_msr_fix_bit(MSR_IA32_VMX_TRUE_ENTRY_CTLS,
				&info->vmentry_fixed0,
				&info->vmentry_fixed1);
	vmx_get_ctl_msr_fix_bit(MSR_IA32_VMX_TRUE_EXIT_CTLS,
				&info->vmexit_fixed0,
				&info->vmexit_fixed1);

	vmx_get_ctl_msr_fix_bit(MSR_IA32_VMX_TRUE_PINBASED_CTLS,
				&info->pin_based_exec_fixed_0,
				&info->pin_based_exec_fixed_1);

	vmx_get_ctl_msr_fix_bit(MSR_IA32_VMX_TRUE_PROCBASED_CTLS,
				&info->proc_based_exec_fixed0,
				&info->proc_based_exec_fixed1);

	proc_based_allowed_1 = ~info->proc_based_exec_fixed0;
	if (proc_based_allowed_1 & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)
		vmx_get_ctl_msr_fix_bit(MSR_IA32_VMX_PROCBASED_CTLS2,
					&info->proc_based_2nd_exec_fixed0,
					&info->proc_based_2nd_exec_fixed1);
	if (proc_based_allowed_1 & CPU_BASED_ACTIVATE_TERTIARY_CONTROLS)
		vmx_get_ctl_msr_fix_bit2(MSR_IA32_VMX_PROCBASED_CTLS3,
					 &info->proc_based_3rd_exec_fixed0,
					 &info->proc_based_3rd_exec_fixed1);

	vmx_get_cr_fix_bit(MSR_IA32_VMX_CR0_FIXED0,
			   MSR_IA32_VMX_CR0_FIXED1,
			   &info->cr0_fixed0, &info->cr0_fixed1);
	vmx_get_cr_fix_bit(MSR_IA32_VMX_CR4_FIXED0,
			   MSR_IA32_VMX_CR4_FIXED1,
			   &info->cr4_fixed0, &info->cr4_fixed1);

	pr_info("pin control: fixed0: 0x%x fixed1:0x%x\n",
		info->pin_based_exec_fixed_0,
		info->pin_based_exec_fixed_1);
	pr_info("proc control: fixed0: 0x%x fixed1:0x%x\n",
		info->proc_based_exec_fixed0,
		info->proc_based_exec_fixed1);
	pr_info("proc 2nd control: fixed0: 0x%x fixed1:0x%x\n",
		info->proc_based_2nd_exec_fixed0,
		info->proc_based_2nd_exec_fixed1);
	pr_info("proc 3rd control: fixed0: 0x%x fixed1:0x%x\n",
		info->proc_based_3rd_exec_fixed0,
		info->proc_based_3rd_exec_fixed1);
	pr_info("vmentry control: fixed0: 0x%x fixed1: 0x%x\n",
		info->vmentry_fixed0, info->vmentry_fixed1);
	pr_info("vmexit control: fixed0: 0x%x fixed1: 0x%x\n",
			info->vmexit_fixed0, info->vmexit_fixed1);
	pr_info("cr0 fixed0: 0x%llx fixed1: 0x%llx\n",
		info->cr0_fixed0, info->cr0_fixed1);
	pr_info("cr4 fixed0: 0x%llx fixed1: 0x%llx\n",
		info->cr4_fixed0, info->cr4_fixed1);

	return 0;
}


static int akvm_ioctl_run(struct file *f, unsigned int ioctl,
			   unsigned long param)
{

	return 0;
}

static int akvm_ioctl_get_vmx_info(struct file *f, unsigned ioctl,
				    unsigned long param)
{
	struct akvm_vmx_info vmx_info;

	vmx_info.vmx_basic_msr = vmx_capability.msr_vmx_basic;
	vmx_info.vmx_misc_msr = vmx_capability.msr_vmx_misc;
	vmx_info.vmx_ept_vpid_msr = vmx_capability.msr_ept_vpid;

	if (copy_to_user((void __user*)param, &vmx_info, sizeof(vmx_info)))
		return -EFAULT;

	return 0;
}

static long akvm_dev_ioctl(struct file *f, unsigned int ioctl,
			   unsigned long param)
{
	int r;

	switch(ioctl) {
	case AKVM_RUN:
		r = akvm_ioctl_run(f, ioctl, param);
		break;
	case AKVM_GET_VMX_INFO:
		r = akvm_ioctl_get_vmx_info(f, ioctl, param);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static struct file_operations akvm_dev_ops = {
	.unlocked_ioctl = akvm_dev_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice akvm_dev = {
	MISC_DYNAMIC_MINOR,
	"akvm",
	&akvm_dev_ops,
};

static int __init akvm_init(void)
{
	int r;

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

static void __exit akvm_exit(void)
{
	misc_deregister(&akvm_dev);
}

module_init(akvm_init);
module_exit(akvm_exit);
MODULE_LICENSE("GPL");
