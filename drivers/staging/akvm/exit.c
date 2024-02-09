#include <linux/printk.h>
#include <linux/module.h>
#include <uapi/linux/akvm.h>
#include <asm/idtentry.h>

#include "exit.h"
#include "mmu.h"
#include "vmx.h"
#include "x86.h"

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

static vm_exit_handler exit_handler[VMX_EXIT_MAX_NUMBER] =
{
	[VMX_EXIT_INTR] = handle_ignore,
	[VMX_EXIT_VMCALL] = handle_vmcall,
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
