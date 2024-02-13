#include <linux/printk.h>
#include <linux/module.h>
#include <uapi/linux/akvm.h>
#include <asm/idtentry.h>

#include "exit.h"
#include "mmu.h"
#include "vmx.h"
#include "x86.h"

#define AKVM_CR0_EMULATE_BITS X86_CR0_NE
#define AKVM_CR4_EMULATE_BITS X86_CR4_VMXE

void __akvm_call_host_intr(unsigned long);
typedef int (*vm_exit_handler)(struct vcpu_context *vcpu);

static int handle_intr_irqoff(struct vcpu_context *vcpu)
{
	unsigned long handler;
	union idt_entry64 *idte;
	struct gdt_idt_table_desc idt_desc;

	if (WARN_ON(!vcpu->intr_info.valid))
		return -EINVAL;

	if (WARN_ON(vcpu->intr_info.type != VMX_INTR_TYPE_EXTERNAL))
		return -EINVAL;

	get_idt_table_desc(&idt_desc);
	idte = (void*)idt_desc.base;
	handler = get_idt_entry_point(idte + vcpu->intr_info.vector);

	__akvm_call_host_intr(handler);
	return 0;
}

static int handle_excep_nmi_irqoff(struct vcpu_context *vcpu)
{
	if (WARN_ON(!vcpu->intr_info.valid))
		return -EINVAL;

	if (WARN_ON(vcpu->intr_info.type != VMX_INTR_TYPE_NMI))
		return -EINVAL;

	__akvm_call_host_intr((unsigned long)asm_exc_nmi_kvm_vmx);
	return 0;
}

static int default_handler(struct vcpu_context *vcpu)
{
	pr_err("unimplemented vm exit reason:%d\n", vcpu->exit.reason);
	return -ENOTSUPP;
}

static int handle_ignore(struct vcpu_context *vcpu)
{
	return 0;
}

static int handle_ept_violation(struct vcpu_context *vcpu)
{
	gpa fault_addr = vmcs_read_64(VMX_EXIT_GPA);

	return akvm_handle_mmu_page_fault(vcpu, &vcpu->vm->mmu, fault_addr);
};

static int handle_vmcall(struct vcpu_context *vcpu)
{
	struct akvm_vcpu_runtime *runtime = vcpu->runtime;

	vcpu->exit_instruction_len =
		vmcs_read_32(VMX_EXIT_INSTRUCTION_LENGTH);

	runtime->exit_reason = AKVM_EXIT_VM_SERVICE;

	runtime->vm_service.type = akvm_vcpu_read_register(vcpu, GPR_RAX);
	runtime->vm_service.in_out[0] = akvm_vcpu_read_register(vcpu, GPR_RDI);
	runtime->vm_service.in_out[1] = akvm_vcpu_read_register(vcpu, GPR_RSI);
	runtime->vm_service.in_out[2] = akvm_vcpu_read_register(vcpu, GPR_RDX);
	runtime->vm_service.in_out[3] = akvm_vcpu_read_register(vcpu, GPR_RCX);
	runtime->vm_service.in_out[4] = akvm_vcpu_read_register(vcpu, GPR_R8);
	runtime->vm_service.in_out[5] = akvm_vcpu_read_register(vcpu, GPR_R9);
	runtime->vm_service.ret =  VM_SERVICE_SUCCESS;

	akvm_vcpu_set_request(vcpu, AKVM_VCPU_REQUEST_VM_SERVICE_COMPLETE,
			      false);
	return 1;
}

static int handle_cr0(struct vcpu_context *vcpu,
		      bool write, int reg_id, unsigned long cr0_new)
{
	unsigned long cr0_shadow;
	unsigned long cr0_guest;
	unsigned long cr0;
	unsigned long guest_own_changes;
	unsigned long host_own_changes;
	unsigned long unsupported = ~AKVM_CR0_EMULATE_BITS;
	unsigned long cr0_guest_mask = ~vcpu->cr0_host_mask;

	if (!write) {
		pr_info("%s: unsupported cr0 read vmexit\n", __func__);
		return -ENOTSUPP;
	}

	/* high 32 bit: Inject #GP */
	if (cr0_new & X86_CR0_RESERVED_HIGH) {
		/* TODO: inject #GP  */
		pr_info("%s: need #GP injection for new cr0: 0x%lx\n", __func__, cr0_new);
		return -ENOTSUPP;
	}

	if (vmx_cap_unrestrict_guest(vcpu->procbase_ctl,
				     vcpu->procbase_2nd_ctl))
		unsupported &= ~(X86_CR0_PG | X86_CR0_PE);

	/*  low 32bit: ignore the reserved bits	*/
	cr0_new &= ~X86_CR0_RESERVED;
	cr0_guest = akvm_vcpu_read_register(vcpu, SYS_CR0);
	cr0_shadow = vmcs_read_natural(VMX_CR0_READ_SHADOW);

	cr0 = (cr0_guest & cr0_guest_mask) | (cr0_shadow & vcpu->cr0_host_mask);
	host_own_changes = (cr0 ^ cr0_new) & vcpu->cr0_host_mask;
	guest_own_changes = (cr0 ^ cr0_new) & cr0_guest_mask;

	WARN_ON(!host_own_changes);

	if (host_own_changes & unsupported) {
		pr_info("%s: unsupported changed bits: 0x%lx\n",
			__func__, host_own_changes);
		return -ENOTSUPP;
	}

	cr0_guest &= ~guest_own_changes;
	cr0_guest |= cr0_new & guest_own_changes;
	akvm_vcpu_write_register(vcpu, SYS_CR0, cr0_guest);

	cr0_shadow &= ~host_own_changes;
	cr0_shadow |= cr0_new & host_own_changes;
	vmcs_write_natural(VMX_CR0_READ_SHADOW, cr0_shadow);
	vcpu->cr0_read_shadow = cr0_shadow;

	return akvm_vcpu_skip_instruction(vcpu);
}

static int handle_cr4(struct vcpu_context *vcpu,
		      bool write, int reg_id, unsigned long cr4_new)
{
	unsigned long cr4_shadow;
	unsigned long cr4_guest;
	unsigned long cr4;
	unsigned long guest_own_changes;
	unsigned long host_own_changes;
	unsigned long unsupported = ~AKVM_CR4_EMULATE_BITS;
	unsigned long cr4_guest_mask = ~vcpu->cr4_host_mask;
	unsigned long reserved;

	if (!write) {
		pr_info("%s: unsupported cr4 read vmexit\n", __func__);
		return -ENOTSUPP;
	}

	reserved = X86_CR4_RESERVED;
	if (boot_cpu_has(X86_FEATURE_LA57))
		reserved &= ~X86_CR4_LA57;

	/* high 32 bit: Inject #GP */
	if (cr4_new & reserved) {
		/* TODO: inject #GP  */
		pr_info("%s: need #GP injection for new cr4: 0x%lx\n", __func__, cr4_new);
		return -ENOTSUPP;
	}

	cr4_guest = akvm_vcpu_read_register(vcpu, SYS_CR4);
	cr4_shadow = vmcs_read_natural(VMX_CR4_READ_SHADOW);

	cr4 = (cr4_guest & cr4_guest_mask) | (cr4_shadow & vcpu->cr4_host_mask);
	host_own_changes = (cr4 ^ cr4_new) & vcpu->cr4_host_mask;
	guest_own_changes = (cr4 ^ cr4_new) & cr4_guest_mask;

	WARN_ON(!host_own_changes);

	if (host_own_changes & unsupported) {
		pr_info("%s: unsupported changed bits: 0x%lx\n",
			__func__, host_own_changes);
		return -ENOTSUPP;
	}

	cr4_guest &= ~guest_own_changes;
	cr4_guest |= cr4_new & guest_own_changes;
	akvm_vcpu_write_register(vcpu, SYS_CR4, cr4_guest);

	cr4_shadow &= ~host_own_changes;
	cr4_shadow |= cr4_new & host_own_changes;
	vmcs_write_natural(VMX_CR4_READ_SHADOW, cr4_shadow);
	vcpu->cr4_read_shadow = cr4_shadow;

	return akvm_vcpu_skip_instruction(vcpu);
}

static int handle_cr(struct vcpu_context *vcpu)
{
	unsigned long qual;
	unsigned long cr;
	unsigned long type;
	unsigned long val;
	unsigned long reg;

	qual = vmcs_read_natural(VMX_EXIT_QUALIFICATION);
	cr = qual & GENMASK_ULL(3, 0);
	type = (qual & GENMASK_ULL(5, 4)) >> 4;
	reg = (qual & GENMASK_ULL(11, 8)) >> 8;
	val = akvm_vcpu_read_register(vcpu, reg);

	if (type >= 2) {
		pr_info("Unsupported CR EXIT: CLTS/LMSW instruction\n");
		return -ENOTSUPP;
	}

	vcpu->exit_instruction_len =
		vmcs_read_32(VMX_EXIT_INSTRUCTION_LENGTH);

	switch (cr) {
	case 0:
		return handle_cr0(vcpu, !type, reg, val);
	case 4:
		return handle_cr4(vcpu, !type, reg, val);
	default:
		break;
	}

	pr_info("Unsupported CR EXIT: cr:0x%lx type:0x%lx reg:0x%lx val:0x%lx\n",
		cr, type, reg, val);
	return -ENOTSUPP;
}

static vm_exit_handler exit_handler[VMX_EXIT_MAX_NUMBER] =
{
	[VMX_EXIT_INTR] = handle_ignore,
	[VMX_EXIT_VMCALL] = handle_vmcall,
	[VMX_EXIT_CR] = handle_cr,
	[VMX_EXIT_EPT_VIOLATION] = handle_ept_violation,
};

int handle_vm_exit_irqoff(struct vcpu_context *vcpu)
{
	switch (vcpu->exit.reason) {
	case VMX_EXIT_EXCEP_NMI:
		return handle_excep_nmi_irqoff(vcpu);
	case VMX_EXIT_INTR:
		return handle_intr_irqoff(vcpu);
	default:
		return 0;
	}
}

int handle_vm_exit(struct vcpu_context *vcpu)
{
	int reason = vcpu->exit.reason;
	vm_exit_handler handler;

	if (reason >= VMX_EXIT_MAX_NUMBER)
		return default_handler(vcpu);

	handler = exit_handler[reason];
	if (!handler)
		return default_handler(vcpu);
	return handler(vcpu);
}

int handle_request_vm_service_complete(struct vcpu_context *vcpu)
{
	struct akvm_vcpu_runtime *rt = vcpu->runtime;

	akvm_vcpu_write_register(vcpu, GPR_RAX, rt->vm_service.ret);
	akvm_vcpu_write_register(vcpu, GPR_RDI, rt->vm_service.in_out[0]);
	akvm_vcpu_write_register(vcpu, GPR_RSI, rt->vm_service.in_out[1]);
	akvm_vcpu_write_register(vcpu, GPR_RDX, rt->vm_service.in_out[2]);
	akvm_vcpu_write_register(vcpu, GPR_RCX, rt->vm_service.in_out[3]);
	akvm_vcpu_write_register(vcpu, GPR_R8, rt->vm_service.in_out[4]);
	akvm_vcpu_write_register(vcpu, GPR_R9, rt->vm_service.in_out[5]);

	return akvm_vcpu_skip_instruction(vcpu);
}
