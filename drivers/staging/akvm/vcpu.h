#ifndef __VCPU_H
#define __VCPU_H

#include <linux/types.h>
#include <linux/preempt.h>
#include <linux/mm.h>
#include <uapi/linux/akvm.h>

#include "common.h"
#include "vmx.h"
#include "vm.h"
#include "x86.h"

enum vcpu_run_state {
	VCPU_IN_HOST,
	VCPU_ENTER_GUEST,
	VCPU_IN_GUEST,
	VCPU_LEAVE_GUEST,
};

enum reg_context_id {
	GPR_RAX = 0,
	GPR_RCX,
	GPR_RDX,
	GPR_RBX,
	GPR_RSP,
	GPR_RBP,
	GPR_RSI,
	GPR_RDI,
	GPR_R8,
	GPR_R9,
	GPR_R10,
	GPR_R11,
	GPR_R12,
	GPR_R13,
	GPR_R14,
	GPR_R15,

	DR_0,
	DR_1,
	DR_2,
	DR_3,
	DR_4,
	DR_5,
	DR_6,
	DR_7,

	SYS_RIP,
	SYS_RFLAGS,
	SYS_CR0,
	SYS_CR2,
	SYS_CR4,
	SYS_CR8,

	REG_MAX,
};
#define VCPU_REG_AVAILABLE_MASK					\
	((1ULL << GPR_RAX) | (1ULL << GPR_RBX) | (1ULL << GPR_RCX) |	\
	 (1ULL << GPR_RDX) | (1ULL << GPR_RDI) | (1ULL << GPR_RSI) |	\
	 (1ULL << GPR_RBP) | /* | (1ULL << GPR_RSP) */ (1ULL << GPR_R8) | \
	 (1ULL << GPR_R9) | (1ULL << GPR_R10) | (1ULL << GPR_R11) |	\
	 (1ULL << GPR_R12) | (1ULL << GPR_R13) | (1ULL << GPR_R14) |	\
	 (1ULL << GPR_R15) /* | (1ULL << SYS_RIP) | (1ULL << SYS_RFLAGS) */)

struct reg_context {
	unsigned long val[REG_MAX];
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
	struct reg_context regs;
	msr_val_t msr_efer;
} __attribute__((packed));

struct vm_vmcs {
	struct list_head entry;
	struct vmx_vmcs *vmcs;
	unsigned long msr_bitmap;
	int launched;
	int last_cpu;
};

#define AKVM_VCPU_REQUEST_FLUSH_TLB 0
#define AKVM_VCPU_REQUEST_VM_SERVICE_COMPLETE 1
#define AKVM_VCPU_REQUEST_EVENT 2

enum exit_info_id {
	EXIT_REASON,
	EXIT_INTR_INFO,
	EXIT_INTR_ERROR_CODE,
	EXIT_INSTRUCTION_LEN,
	EXIT_GPA,
	EXIT_VECTOR_INFO,
	EXIT_VECTOR_ERROR_CODE,
	EXIT_INFO_QUAL,
	EXIT_INFO_MAX,
};

struct exit_info {
	unsigned long val[EXIT_INFO_MAX];
};

enum event_inject_state
{
	EVENT_FREE,
	EVENT_PENDING,
	EVENT_INJECTED,
};

struct exception_inject_state {
	int id;
	int instruction_len;
	bool has_error_code;
	unsigned long error_code;
	enum event_inject_state state;
	enum event_inject_state nmi_state;
	enum x86_event_type type;
};

struct vcpu_context {
	struct vm_vmcs vmcs;

	unsigned int pinbase_ctl;
	unsigned int procbase_ctl;
	unsigned int procbase_2nd_ctl;
	unsigned int entry_ctl;
	unsigned int exit_ctl;
	unsigned long cr0_host_mask;
	unsigned long cr0_read_shadow;
	unsigned long cr4_host_mask;
	unsigned long cr4_read_shadow;
	unsigned int vpid;

	struct exit_info exit_info;
	unsigned long exit_info_available_mask;

	struct vm_host_state host_state;
	struct vm_guest_state guest_state;
	struct exception_inject_state exception;

	struct mutex ioctl_lock;
	struct preempt_notifier preempt_notifier;
	struct file *vm_file;
	struct vm_context *vm;

	int index;
	atomic_t run_state;
	unsigned long requests;
	unsigned long regs_available_mask;
	unsigned long regs_dirty_mask;

	struct akvm_vcpu_runtime  *runtime;
	struct akvm_cpuid cpuid;
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
	atomic_set(&vcpu->run_state, VCPU_IN_HOST);
}

unsigned long akvm_vcpu_read_register(struct vcpu_context *vcpu,
				      enum reg_context_id id);
void akvm_vcpu_write_register(struct vcpu_context *vcpu,
			      enum reg_context_id id,
			      unsigned long val);
int akvm_vcpu_skip_instruction(struct vcpu_context *vcpu);

void akvm_vcpu_intercept_msr_read(struct vcpu_context *vcpu, unsigned int msr);
void akvm_vcpu_intercept_msr_write(struct vcpu_context *vcpu, unsigned int msr);
void akvm_vcpu_passthru_msr_read(struct vcpu_context *vcpu, unsigned int msr);
void akvm_vcpu_passthru_msr_write(struct vcpu_context *vcpu, unsigned int msr);

unsigned long akvm_vcpu_exit_info(struct vcpu_context *vcpu,
				  enum exit_info_id id);

int akvm_vcpu_inject_exception(struct vcpu_context *vcpu, int excep_number,
			       bool has_error_code, unsigned long error_code,
			       enum x86_event_type type,
			       unsigned long pay_load,
			       int instruction_len);
/* friendly API for most used exceptions :-) */
int akvm_vcpu_inject_gp(struct vcpu_context *vcpu, unsigned long error_code);
void akvm_vcpu_set_immediate_exit(struct vcpu_context *vcpu);
void akvm_vcpu_clear_immediate_exit(struct vcpu_context *vcpu);

#define NO_SUB_LEAF 0xfffffffe
struct akvm_cpuid_entry *akvm_vcpu_find_cpuid(struct akvm_cpuid *cpuid,
					      int leaf, int sub_leaf);
#endif
