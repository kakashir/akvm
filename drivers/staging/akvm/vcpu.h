#ifndef __VCPU_H
#define __VCPU_H

#include <linux/types.h>
#include <linux/preempt.h>
#include <linux/mm.h>

#include "common.h"
#include "vm.h"

enum vcpu_run_state {
	VCPU_IN_HOST,
	VCPU_ENTER_GUEST,
	VCPU_IN_GUEST,
	VCPU_LEAVE_GUEST,
};

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

#define AKVM_VCPU_REQUEST_FLUSH_TLB 0

struct vcpu_context {
	struct vm_vmcs vmcs;

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

	struct mutex ioctl_lock;
	struct preempt_notifier preempt_notifier;
	struct file *vm_file;
	struct vm_context *vm;

	int index;
	atomic_t run_state;
	unsigned long requests;
};

int akvm_create_vcpu(struct file *vm_file,
		     struct vm_context *vm, int vcpu_index);
void akvm_vcpu_kick(struct vcpu_context *vcpu);
void akvm_vcpu_set_request(struct vcpu_context *vcpu, unsigned long request,
			   bool urgent);
void akvm_vcpu_sched_in(struct preempt_notifier *pn, int cpu);
void akvm_vcpu_sched_out(struct preempt_notifier *pn,
			 struct task_struct *next);

static inline int set_run_state(struct vcpu_context *vcpu,
				 int from, int to)
{
	return atomic_cmpxchg(&vcpu->run_state,
				 from, to);
}

static inline bool set_run_state_enter_guest(struct vcpu_context *vcpu)
{
	return VCPU_IN_HOST ==
		set_run_state(vcpu, VCPU_IN_HOST, VCPU_ENTER_GUEST);
}

static inline void set_run_state_in_guest(struct vcpu_context *vcpu)
{
	int old = set_run_state(vcpu, VCPU_ENTER_GUEST, VCPU_IN_GUEST);

	WARN_ON(old != VCPU_ENTER_GUEST);
}

static inline void set_run_state_leave_guest(struct vcpu_context *vcpu)
{
	int old = set_run_state(vcpu, VCPU_IN_GUEST, VCPU_LEAVE_GUEST);

	WARN_ON(old != VCPU_IN_GUEST);
}

static inline void set_run_state_in_host(struct vcpu_context *vcpu)
{
	int old = set_run_state(vcpu, VCPU_LEAVE_GUEST, VCPU_IN_HOST);

	WARN_ON(old != VCPU_LEAVE_GUEST);
}

#endif
