#include "vmx.h"

#ifdef _DEBUG
#define vmx_pr_info  pr_info
#else
#define vmx_pr_info(...)
#endif

int probe_vmx_basic_info(struct vmx_capability *info)
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
	if (proc_based_allowed_1 & VMX_PROCBASE_ACTIVE_2ND_CONTROL)
		vmx_get_ctl_msr_fix_bit(MSR_IA32_VMX_PROCBASED_CTLS2,
					&info->proc_based_2nd_exec_fixed0,
					&info->proc_based_2nd_exec_fixed1);
	if (proc_based_allowed_1 & VMX_PROCBASE_ACTIVE_3RD_CONTROL)
		vmx_get_ctl_msr_fix_bit2(MSR_IA32_VMX_PROCBASED_CTLS3,
					 &info->proc_based_3rd_exec_fixed0,
					 &info->proc_based_3rd_exec_fixed1);

	vmx_get_cr_fix_bit(MSR_IA32_VMX_CR0_FIXED0,
			   MSR_IA32_VMX_CR0_FIXED1,
			   &info->cr0_fixed0, &info->cr0_fixed1);
	vmx_get_cr_fix_bit(MSR_IA32_VMX_CR4_FIXED0,
			   MSR_IA32_VMX_CR4_FIXED1,
			   &info->cr4_fixed0, &info->cr4_fixed1);

	vmx_pr_info("pin control: fixed0: 0x%x fixed1:0x%x\n",
		info->pin_based_exec_fixed_0,
		info->pin_based_exec_fixed_1);
	vmx_pr_info("proc control: fixed0: 0x%x fixed1:0x%x\n",
		info->proc_based_exec_fixed0,
		info->proc_based_exec_fixed1);
	vmx_pr_info("proc 2nd control: fixed0: 0x%x fixed1:0x%x\n",
		info->proc_based_2nd_exec_fixed0,
		info->proc_based_2nd_exec_fixed1);
	vmx_pr_info("proc 3rd control: fixed0: 0x%llx fixed1:0x%llx\n",
		info->proc_based_3rd_exec_fixed0,
		info->proc_based_3rd_exec_fixed1);
	vmx_pr_info("vmentry control: fixed0: 0x%x fixed1: 0x%x\n",
		info->vmentry_fixed0, info->vmentry_fixed1);
	vmx_pr_info("vmexit control: fixed0: 0x%x fixed1: 0x%x\n",
			info->vmexit_fixed0, info->vmexit_fixed1);
	vmx_pr_info("cr0 fixed0: 0x%llx fixed1: 0x%llx\n",
		info->cr0_fixed0, info->cr0_fixed1);
	vmx_pr_info("cr4 fixed0: 0x%llx fixed1: 0x%llx\n",
		info->cr4_fixed0, info->cr4_fixed1);

	return 0;
}

void prepare_vmx_region(struct vmx_region *region,
			       unsigned int size,
			       unsigned int revision)
{
	memset(region, 0, size);
	region->revision = revision;
}

int vmx_on(struct vmx_region *vmx_region)
{
	unsigned long pa = __pa(vmx_region);

	cr4_set_bits(X86_CR4_VMXE);
	asm volatile goto("1: vmxon %0\n\t"
		 "jc %l[failinvalid]\n\t"
		 _ASM_EXTABLE(1b, %l[fault])
		 : : "m"(pa)
		 : : fault, failinvalid);
	vmx_pr_info("VMXON!\n");
	return 0;
 fault:
	pr_err("VMXON failed:0x%lx\n", (unsigned long)vmx_region);
	cr4_clear_bits(X86_CR4_VMXE);
	return -EFAULT;
 failinvalid:
	pr_err("VMXON VMfailedInvalid:0x%lx\n", (unsigned long)vmx_region);
	return -EINVAL;
}

void vmx_off(void)
{
	asm volatile goto("1: vmxoff\n\r"
		 _ASM_EXTABLE(1b, %l[fault])
		 : : : : fault);
 fault:
	cr4_clear_bits(X86_CR4_VMXE);
	vmx_pr_info("VMXOFF!\n");
}

void prepare_vmcs(struct vmx_vmcs *vmcs, unsigned int size,
			 unsigned int revision)
{
	memset(vmcs, 0, size);
	vmcs->revision = revision;
	vmcs->shadow = 0;
	vmcs->abort = 0;
	/* SDM3 25.11.3 */
	vmcs_clear(vmcs);
}

int vmcs_load(struct vmx_vmcs *vmcs)
{
	unsigned long pa = __pa(vmcs);

	asm volatile goto("1: vmptrld %0\n\t"
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

void vmcs_clear(struct vmx_vmcs *vmcs)
{
	unsigned long pa = __pa(vmcs);

	asm volatile goto("1: vmclear %0\n\t"
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
	pr_err("vmcs_clear() VMfailed:0x%lx instruction error:%ld\n",
	       (unsigned long)vmcs,
	       vmcs_read_32(VMX_INSTRUCTION_ERROR));
	return;
 failinvalid:
	pr_err("vmcs_clear() VMfailedInvalid:0x%lx\n", (unsigned long)vmcs);
	return;
}

unsigned long __vmcs_read(vmcs_field field)
{
	unsigned long val;

	asm volatile goto("mov %1, %%eax\n\t"
		 "1: vmread %%rax, %0\n\t"
		 "jz %l[fail]\n\t"
		 "jc %l[failinvalid]\n\t"
		 _ASM_EXTABLE(1b, %l[fault])
		 :"=m"(val)
		 :"q"(field)
		 : : fault, fail, failinvalid);
	return val;
 fault:
	pr_err("%s() fault: field:0x%x\n", __func__, field);
	return -1;
 fail:
	pr_err("%s() VMfailed: field:0x%x\n", __func__, field);
	return -1;
 failinvalid:
	pr_err("%s() VMfailedInvalid: field:0x%x\n", __func__, field);
	return -1;
}

void __vmcs_write(vmcs_field field, unsigned long val)
{
	asm volatile goto("mov %1, %%eax\n\t"
		 "1: vmwrite %0, %%rax\n\t"
		 "jz %l[fail]\n\t"
		 "jc %l[failinvalid]\n\t"
		 _ASM_EXTABLE(1b, %l[fault])
		 : : "m"(val), "q"(field)
		 : "memory"
		 : fault, fail, failinvalid);
	return;
 fault:
	pr_err("%s() fault: field:0x%x\n", __func__, field);
	return;
 fail:
	pr_err("%s() VMfailed: field:0x%x\n", __func__, field);
	return;
 failinvalid:
	pr_err("%s() VMfailedInvalid: field:0x%x\n", __func__, field);
	return;
}

bool vmx_need_vmentry_instruction_len(enum x86_event_type type)
{
	if (type == X86_EVENT_SOFTWARE_INTR)
		return true;
	if (type == X86_EVENT_SOFTWARE_EXCEP)
		return true;
	if (type == X86_EVENT_PRIV_SOFTWARE_EXCEP)
		return true;
	return false;
}

void vmx_inject_event(int vector, enum x86_event_type type,
		      bool has_error_code, unsigned long error_code,
		      int instruction_len)
{
	union vmx_intr_info event = {
		.vector = vector,
		.type = type,
		.error_code = has_error_code,
		.iret_nmi_block = 0,
		.valid = 1,
	};

	vmcs_write_32(VMX_ENTRY_EVENT_INFO, event.val);
	if (has_error_code)
		vmcs_write_32(VMX_ENTRY_EVENT_ERROR_CODE, error_code);
	if (vmx_need_vmentry_instruction_len(type))
		vmcs_write_32(VMX_ENTRY_INSTRUCTION_LEN, instruction_len);
}

bool vmx_inject_event_need_set_flags_rf(int vector)
{
	switch (vector) {
	case X86_EXCEP_DE:
	case X86_EXCEP_BR:
	case X86_EXCEP_UD:
	case X86_EXCEP_NM:
	case X86_EXCEP_9:
	case X86_EXCEP_TS:
	case X86_EXCEP_NP:
	case X86_EXCEP_SS:
	case X86_EXCEP_GP:
	case X86_EXCEP_PF:
	case X86_EXCEP_MF:
	case X86_EXCEP_AC:
	case X86_EXCEP_XM:
	case X86_EXCEP_VE:
	case X86_EXCEP_CP:
		return true;
	default:
		return false;
	}

}

int invept(unsigned long ept_root, struct vmx_capability *vmx_cap)
{
	if (!vmx_ept_invept_supported(vmx_cap))
		return -ENOTSUPP;

	if (!vmx_ept_invept_single_context(vmx_cap) && ept_root)
		ept_root = 0;

	if (!vmx_ept_invept_all_context(vmx_cap) && !ept_root)
		return -ENOTSUPP;
	return __invept(ept_root);
}
