#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

#include <uapi/linux/akvm.h>

#include <asm/msr-index.h>
#include <asm/vmx.h>
#include <asm/cpu_entry_area.h>

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

static void vmx_get_ctl_msr_fix_bit2(int msr, u64 *ctl_fix_0, u64 *ctl_fix_1)
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

#define vmx_check_ctl_bit(val, expect_val) \
	(((val) & (expect_val)) == (expect_val))

#define  vmx_adjust_ctl_bit(val, fixed0, fixed1) \
{ \
	(val) &= ~(fixed0);			\
	(val) |= (fixed1);			\
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
	pr_info("proc 3rd control: fixed0: 0x%llx fixed1:0x%llx\n",
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

static struct vm_context vm_context;

static int vmx_on(struct vmx_region *vmx_region)
{
	unsigned long pa = __pa(vmx_region);

	cr4_set_bits(X86_CR4_VMXE);
	asm_volatile_goto("1: vmxon %0\n\t"
			  "jc %l[failinvalid]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  : : "m"(pa)
			  : : fault, failinvalid);
	pr_info("VMXON!\n");
	return 0;
 fault:
	pr_err("VMXON failed:0x%lx\n", (unsigned long)vmx_region);
	cr4_clear_bits(X86_CR4_VMXE);
	return -EFAULT;
 failinvalid:
	pr_err("VMXON VMfailedInvalid:0x%lx\n", (unsigned long)vmx_region);
	return -EINVAL;
}

static void vmx_off(void)
{
	asm_volatile_goto("1: vmxoff\n\r"
			  _ASM_EXTABLE(1b, %l[fault])
			  : : : : fault);
 fault:
	cr4_clear_bits(X86_CR4_VMXE);
	pr_info("VMXOFF!\n");
}

static void free_vmcs(struct vm_context *vm)
{
	/* kfree takes care NULL ptr */
	kfree(vm->vmx_region);
	kfree(vm->vmcs);
}

static int alloc_vmcs(struct vm_context *vm)
{
	size_t size = vmx_region_size(&vmx_capability);

	vm->vmx_region = kmalloc(size, GFP_KERNEL_ACCOUNT);
	if (!vm->vmx_region) {
		pr_err("failed to alloc vmxon region\n");
		return -ENOMEM;
	}

	vm->vmcs = kmalloc(size, GFP_KERNEL_ACCOUNT);
	if (!vm->vmcs) {
		pr_err("failed to alloc vmcs\n");
		goto failed_free;
	}

	return 0;

 failed_free:
	free_vmcs(vm);
	return -ENOMEM;
}

static int vmcs_load(struct vmx_vmcs *vmcs)
{
	unsigned long pa = __pa(vmcs);

	asm_volatile_goto("1: vmptrld %0\n\t"
			  "jz %l[fail]\n\t"
			  "jc %l[failinvalid]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  : :"m"(pa)
			  : "cc"
			  : fault, fail, failinvalid);

	return 0;
 fault:
	pr_err("vmcs_load() fault:0x%lx\n", (unsigned long)vmcs);
	return -EFAULT;
 fail:
	pr_err("vmcs_load() VMfailed:0x%lx instruction error:0x%ld\n",
	       (unsigned long)vmcs,
	       vmcs_read_32(VMX_INSTRUCTION_ERROR));
	return -EINVAL;
 failinvalid:
	pr_err("vmcs_load() VMfailedInvalid:0x%lx\n", (unsigned long)vmcs);
	return -EINVAL;
}

static void vmcs_clear(struct vmx_vmcs *vmcs)
{
	unsigned long pa = __pa(vmcs);

	asm_volatile_goto("1: vmclear %0\n\t"
			  "jz %l[fail]\n\t"
			  "jc %l[failinvalid]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  : :"m"(pa)
			  : "cc"
			  : fault, fail, failinvalid);
	return;
 fault:
	pr_err("vmcs_clear() fault:0x%lx\n", (unsigned long)vmcs);
	return;
 fail:
	/* TODO: Read instruction error from vmcs  */
	pr_err("vmcs_clear() VMfailed:0x%lx instruction error:%ld\n",
	       (unsigned long)vmcs,
	       vmcs_read_32(VMX_INSTRUCTION_ERROR));
	return;
 failinvalid:
	pr_err("vmcs_clear() VMfailedInvalid:0x%lx\n", (unsigned long)vmcs);
	return;
}


static void prepare_vmx_region(struct vmx_region *region,
			       unsigned int size,
			       unsigned int revision)
{
	memset(region, 0, size);
	region->revision = revision;
}

static void prepare_vmcs(struct vmx_vmcs *vmcs, unsigned int size,
			 unsigned int revision)
{
	memset(vmcs, 0, size);
	vmcs->revision = revision;
	vmcs->shadow = 0;
	vmcs->abort = 0;
	/* SDM3 25.11.3 */
	vmcs_clear(vmcs);
}

static int setup_vmcs_control(struct vm_context *vm,
			       struct vmx_capability *cap)
{
	unsigned int vmx_pinbase = VMX_EXEC_CTL_MIN;
	unsigned int vmx_procbase = VMX_PROCBASE_CTL_MIN;
	unsigned int vmx_procbase_2nd = VMX_PROCBASE_2ND_CTL_MIN;
	unsigned int vmx_entry = VMX_ENTRY_CTL_MIN;
	unsigned int vmx_exit  = VMX_EXIT_CTL_MIN;

	vmx_adjust_ctl_bit(vmx_pinbase,
			   cap->pin_based_exec_fixed_0,
			   cap->pin_based_exec_fixed_1);
	if (!vmx_check_ctl_bit(vmx_pinbase, VMX_EXEC_CTL_MIN)) {
		pr_err("unsupported vmx pinbase:0x%x\n", vmx_pinbase);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_procbase,
			   cap->proc_based_exec_fixed0,
			   cap->proc_based_exec_fixed1);
	if (!vmx_check_ctl_bit(vmx_procbase, VMX_PROCBASE_CTL_MIN)) {
		pr_err("unsupported vmx procbase:0x%x\n", vmx_procbase);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_procbase_2nd,
			   cap->proc_based_2nd_exec_fixed0,
			   cap->proc_based_2nd_exec_fixed1);
	if (!vmx_check_ctl_bit(vmx_procbase_2nd, VMX_PROCBASE_2ND_CTL_MIN)) {
		pr_err("unsupported vmx procbase 2nd:0x%x\n", vmx_procbase_2nd);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_entry,
			   cap->vmentry_fixed0, cap->vmentry_fixed1);
	if (!vmx_check_ctl_bit(vmx_entry, VMX_ENTRY_CTL_MIN)) {
		pr_err("unsupported vmx entry:0x%x\n", vmx_entry);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_exit,
			   cap->vmexit_fixed0, cap->vmexit_fixed1);
	if (!vmx_check_ctl_bit(vmx_exit, VMX_EXIT_CTL_MIN)) {
		pr_err("unsupported vmx exit:0x%x\n", vmx_exit);
		return -EINVAL;
	}

	vmcs_write_32(VMX_PINBASE_CTL, vmx_pinbase);
	vmcs_write_32(VMX_PROCBASE_CTL, vmx_procbase);
	vmcs_write_32(VMX_PROCBASE_2ND_CTL, vmx_procbase_2nd);
	vmcs_write_32(VMX_ENTRY_CTL, vmx_entry);
	vmcs_write_32(VMX_EXIT_CTL, vmx_exit);

	vm->pinbase_ctl = vmx_pinbase;
	vm->procbase_ctl = vmx_procbase;
	vm->procbase_2nd_ctl = vmx_procbase_2nd;
	vm->entry_ctl = vmx_entry;
	vm->exit_ctl = vmx_exit;

	return 0;
}

static int setup_vmcs_host_state(struct vm_context *vm)
{
	extern void akvm_vmx_vmexit(void);

	union {
		struct {
			unsigned int low;
			unsigned int high;
		};
		unsigned long val;
	} msr_val;

	struct gdt_idt_table_desc gdt_idt_desc;
	int cpu = smp_processor_id();

	/*
	  CR0 CR3 CR4
	  RSP RIP are handled before vmlaunch/vmresume
	  CS SS DS ES FS GS TR selector
	  FS GS TR GDTR IDTR Base

	  Question:
		GDT/IDT's limit will be set to 0xffff by hardware
		Does this become kind of issue now?

	  IA32_SYSENTER_CS
	  IA32_SYSENTER_ESP
	  IA32_SYSENTER_EIP
	  IA32_PERF_GLOBAL_CTRL
	  IA32_PAT
	  IA32_EFER
	  IA32_PKRS
	  IA32_S_CET (not need now)
	  IA32_INETRRUPT_SSP_TABLE_ADDR (not need now)
	 */
	vmcs_write_natural(VMX_HOST_CR0, read_cr0());
	vmcs_write_natural(VMX_HOST_CR3, __read_cr3());
	vmcs_write_natural(VMX_HOST_CR4, __read_cr4());

	vmcs_write_natural(VMX_HOST_RIP, (unsigned long)akvm_vmx_vmexit);

	vmcs_write_16(VMX_HOST_CS, get_cs());
	vmcs_write_16(VMX_HOST_SS, get_ss());
	vmcs_write_16(VMX_HOST_DS, get_ds());
	vmcs_write_16(VMX_HOST_ES, get_es());
	vmcs_write_16(VMX_HOST_FS, get_fs());
	vmcs_write_16(VMX_HOST_GS, get_gs());
	vmcs_write_16(VMX_HOST_TR, get_tr());

	vmcs_write_natural(VMX_HOST_FS_BASE, get_fsbase());
	pr_info("fsbase: 0x%lx\n", get_fsbase());

	vmcs_write_natural(VMX_HOST_GS_BASE, get_gsbase());
	pr_info("gsbase: 0x%lx\n", get_gsbase());

	vmcs_write_natural(VMX_HOST_TR_BASE,
			   (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
	pr_info("tr_base: 0x%lx\n", (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);

	get_gdt_table_desc(&gdt_idt_desc);
	vmcs_write_natural(VMX_HOST_GDT_BASE, gdt_idt_desc.base);
	pr_info("gdt: base:0x%lx size:%d\n",
		gdt_idt_desc.base, (int)gdt_idt_desc.size);

	get_idt_table_desc(&gdt_idt_desc);
	vmcs_write_natural(VMX_HOST_IDT_BASE, gdt_idt_desc.base);
	pr_info("idt: base:0x%lx size:%d\n",
		gdt_idt_desc.base, (int)gdt_idt_desc.size);

	rdmsr(MSR_IA32_SYSENTER_CS, msr_val.low, msr_val.high);
	vmcs_write_32(VMX_HOST_IA32_SYSENTER_CS, msr_val.low);
	pr_info("sysenter_cs: 0x%x\n", msr_val.low);

	rdmsr(MSR_IA32_SYSENTER_ESP, msr_val.low, msr_val.high);
	vmcs_write_natural(VMX_HOST_IA32_SYSENTER_ESP, msr_val.val);
	pr_info("sysenter_esp: 0x%lx\n", msr_val.val);

	rdmsr(MSR_IA32_SYSENTER_EIP, msr_val.low, msr_val.high);
	vmcs_write_natural(VMX_HOST_IA32_SYSENTER_EIP, msr_val.val);
	pr_info("sysenter_eip: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_PERF_GLOBAL_CTL, msr_val.val);
	pr_info("perf_global_ctl: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_IA32_CR_PAT, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_PAT, msr_val.val);
	pr_info("ia32_pat: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_EFER, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_EFER, msr_val.val);
	pr_info("ia32_efer: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_IA32_PKRS, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_PKRS, msr_val.val);
	pr_info("ia32_pkrs: 0x%lx\n", msr_val.val);

	return 0;
}

asmlinkage unsigned long
__akvm_vcpu_run(struct vm_host_state *hs, struct vm_guest_state *gs,
		int launched);

static int vm_enter_exit(struct vm_context *vm)
{
	unsigned long r;
	unsigned long flags;

	local_irq_save(flags);
	r = __akvm_vcpu_run(&vm->host_state, &vm->guest_state,
			    vm->launched);
	local_irq_restore(flags);
	if (r) {
		switch(r) {
		case 1:
			pr_err("failed vmentry: instruction error:0x%lx\n",
			       vmcs_read_32(VMX_INSTRUCTION_ERROR));
			break;
		case 2:
			pr_err("failedInvalid vmentry:\n");
			break;
		default:
			pr_err("failed unknown\n");
			break;
		}

		return r;
	}

	vm->launched = true;
	return r;
}

static int akvm_ioctl_run(struct file *f, unsigned long param)
{
	/*
	  prepare VMCS and sub struct
		alloc vmcs and sub struct
	  PREEMPTION_DISABLE()
	  VMX ON
		setup exec/vmetnry/vmexit control fields
	  load vmcs
	  prepare host state
	  prepare guest state
	  vmlaunch

	  vmcs clear
	  free vmcs
	  VMX OFF
	  PREEMPTION_ENABLE()
	 */
	int r;

	r = alloc_vmcs(&vm_context);
	if (r)
		return r;

	prepare_vmx_region(vm_context.vmx_region,
			   vmx_region_size(&vmx_capability),
			   vmx_vmcs_revision(&vmx_capability));
	preempt_disable();
	vmx_on(vm_context.vmx_region);
	prepare_vmcs(vm_context.vmcs,
		     vmx_region_size(&vmx_capability),
		     vmx_vmcs_revision(&vmx_capability));
	vmcs_load(vm_context.vmcs);

	r = setup_vmcs_control(&vm_context, &vmx_capability);
	if (r)
		goto exit;
	r = setup_vmcs_host_state(&vm_context);
	if (r)
		goto exit;
	r = vm_enter_exit(&vm_context);
	if (r)
		goto exit;

 exit:
	vmcs_clear(vm_context.vmcs);
	vmx_off();
	preempt_enable();

	free_vmcs(&vm_context);
	return r;
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

static long akvm_dev_ioctl(struct file *f, unsigned int ioctl,
			   unsigned long param)
{
	int r;

	switch(ioctl) {
	case AKVM_RUN:
		r = akvm_ioctl_run(f, param);
		break;
	case AKVM_GET_VMX_INFO:
		r = akvm_ioctl_get_vmx_info(f, param);
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
