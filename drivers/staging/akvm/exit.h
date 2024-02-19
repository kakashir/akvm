#ifndef __EXIT_H
#define __EXIT_H

#include <linux/types.h>
#include "vcpu.h"

#define AKVM_CR0_EMULATE_BITS (X86_CR0_NE | X86_CR0_PG | X86_CR0_PE)
#define AKVM_CR4_EMULATE_BITS (X86_CR4_VMXE | X86_CR4_PAE)

int handle_vm_exit(struct vcpu_context *vcpu, union vmx_exit_reason exit);
int handle_vm_exit_irqoff(struct vcpu_context *vcpu,
			  union vmx_exit_reason exit);
int handle_request_vm_service_complete(struct vcpu_context *vcpu);

#endif
