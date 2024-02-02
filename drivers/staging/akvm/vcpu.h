#ifndef __VCPU_H
#define __VCPU_H

#include <linux/types.h>
#include <linux/preempt.h>
#include <linux/mm.h>

#include "common.h"

enum gpr_context_id {
	GPR_RAX = 0,
	GPR_RBX,
	GPR_RCX,
	GPR_RDX,
	GPR_RDI,
	GPR_RSI,
	GPR_RBP,
	GPR_RSP,
	GPR_R8,
	GPR_R9,
	GPR_R10,
	GPR_R11,
	GPR_R12,
	GPR_R13,
	GPR_R14,
	GPR_R15,
};

struct gpr_context {
	unsigned long rax;
	unsigned long rbx;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rdi;
	unsigned long rsi;
	unsigned long rbp;
	unsigned long rsp;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
} __attribute__((packed));

struct vm_host_state {
	/* sync with asm part */
	unsigned long rflags;
	unsigned long cr8;

	unsigned long dr[8];

	unsigned long msr_debugctl;
	unsigned long msr_rtit_ctl;
	unsigned long msr_lbr_ctl;


} __attribute__((packed));

struct vm_guest_state {
	struct gpr_context gprs;
	unsigned long cr2;
	unsigned long cr8;
} __attribute__((packed));

struct vm_vmcs {
	struct list_head entry;
	struct vmx_vmcs *vmcs;
	int launched;
	int last_cpu;
};

struct vcpu_context {
	struct vm_vmcs vmcs;
	unsigned long ept_root;

	unsigned int pinbase_ctl;
	unsigned int procbase_ctl;
	unsigned int procbase_2nd_ctl;
	unsigned int entry_ctl;
	unsigned int exit_ctl;

	union vmx_exit_reason exit;
	union vmx_intr_info intr_info;
	int intr_error_code;

	struct vm_host_state host_state;
	struct vm_guest_state guest_state;

	struct preempt_notifier preempt_notifier;
	struct file *vm_file;
};

int akvm_create_vcpu(struct file *vm_file);
void akvm_vcpu_sched_in(struct preempt_notifier *pn, int cpu);
void akvm_vcpu_sched_out(struct preempt_notifier *pn,
			 struct task_struct *next);

#endif
