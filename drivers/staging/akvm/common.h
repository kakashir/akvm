#ifndef _AKVM_COMMON_H_
#define _AKVM_COMMON_H_

#include <linux/mm.h>

#define __FUNC_TRACE__(text) pr_info("%s() " #text "\n", __func__);
#define FUNC_ENTRY()  __FUNC_TRACE__("ENTRY")
#define FUNC_EXIT()  __FUNC_TRACE__("EXIT")

struct vmx_capability
{
	u64 msr_vmx_basic;
	u64 msr_vmx_misc;
	u64 msr_ept_vpid;

	/*
	  1 in XX_fixed0: bits shuold be 0
	  1 in XX_fixed1: bits should be 1
	 */
	u32 pin_based_exec_fixed_0;
	u32 pin_based_exec_fixed_1;

	u32 proc_based_exec_fixed0;
	u32 proc_based_exec_fixed1;
	u32 proc_based_2nd_exec_fixed0;
	u32 proc_based_2nd_exec_fixed1;
	u64 proc_based_3rd_exec_fixed0;
	u64 proc_based_3rd_exec_fixed1;

	u32 vmentry_fixed0;
	u32 vmentry_fixed1;

	u32 vmexit_fixed0;
	u32 vmexit_fixed1;

	u64 cr0_fixed0;
	u64 cr0_fixed1;

	u64 cr4_fixed0;
	u64 cr4_fixed1;
};

static inline unsigned int vmx_vmcs_revision(struct vmx_capability *vmx_cap)
{
	return vmx_cap->msr_vmx_basic & GENMASK(30, 0);
}

static inline unsigned int vmx_region_size(struct vmx_capability *vmx_cap)
{
	return PAGE_ALIGN((vmx_cap->msr_vmx_basic & GENMASK(44, 32)) >> 32);
}

static inline unsigned int  vmx_mem_type(struct vmx_capability *vmx_cap)
{
	return (vmx_cap->msr_vmx_basic & GENMASK(53, 50)) >> 50;
}

static inline bool vmx_true_vmx_ctl(struct vmx_capability *vmx_cap)
{
	return !!(vmx_cap->msr_vmx_basic & BIT_ULL(55));
}

static inline int vmx_ept_level(struct vmx_capability *vmx_cap)
{
	if (vmx_cap->msr_ept_vpid & BIT(6))
		return 4;

	if (vmx_cap->msr_ept_vpid & BIT(7))
		return 5;

	WARN_ON(1);
	return 4;
}

static inline bool vmx_ept_mem_type_wb(struct vmx_capability *vmx_cap)
{
	return !!(vmx_cap->msr_ept_vpid & BIT(14));
}

static inline bool vmx_ept_mem_type_uc(struct vmx_capability *vmx_cap)
{
	return !!(vmx_cap->msr_ept_vpid & BIT(8));
}

static inline bool vmx_ept_ad_bit(struct vmx_capability *vmx_cap)
{
	return !!(vmx_cap->msr_ept_vpid & BIT(21));
}

struct vmx_region
{
	u32 revision:31;
};

/* VMCS only has valid head definition */
struct vmx_vmcs
{
	u32 revision:31;
	u32 shadow:1;
	u32 abort;
};

enum gpr_context_id
{
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

struct gpr_context
{
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

struct vm_host_state
{
	/* sync with asm part */
	struct gpr_context gprs;
	unsigned long rflags;

	unsigned long cr2;
} __attribute__((packed));

struct vm_guest_state
{
	struct gpr_context gprs;

	unsigned long cr2;
} __attribute__((packed));

struct vm_context
{
	struct vmx_region  *vmx_region;
	struct vmx_vmcs *vmcs;
	unsigned long ept_root;

	unsigned int pinbase_ctl;
	unsigned int procbase_ctl;
	unsigned int procbase_2nd_ctl;
	unsigned int entry_ctl;
	unsigned int exit_ctl;
	int launched;

	struct vm_host_state host_state;
	struct vm_guest_state guest_state;
};

/* VMX feilds */
typedef unsigned int vmcs_field;
enum vmcs_filed_id {
	VMX_INSTRUCTION_ERROR = 0x4400,
	VMX_EXIT_REASON = 0x4402,

	VMX_PINBASE_CTL = 0x4000,
	VMX_PROCBASE_CTL = 0x4002,
	VMX_PROCBASE_2ND_CTL = 0x401e,
	VMX_EPTP_POINTER = 0x201a,
	VMX_ENTRY_CTL = 0x4012,
	VMX_EXIT_CTL = 0x400c,

	/* host 16bit state area */
	VMX_HOST_ES = 0xc00,
	VMX_HOST_CS = 0xc02,
	VMX_HOST_SS = 0xc04,
	VMX_HOST_DS = 0xc06,
	VMX_HOST_FS = 0xc08,
	VMX_HOST_GS = 0xc0a,
	VMX_HOST_TR = 0xc0c,

	/* host 32bit state area */
	VMX_HOST_IA32_SYSENTER_CS = 0x4c00,

	/* host 64bit state area */
	VMX_HOST_IA32_PAT = 0x2c00,
	VMX_HOST_IA32_PAT_HIGH = 0x2c01,
	VMX_HOST_IA32_EFER = 0x2c02,
	VMX_HOST_IA32_EFER_HIGH = 0x2c03,
	VMX_HOST_IA32_PERF_GLOBAL_CTL = 0x2c04,
	VMX_HOST_IA32_PERF_GLOBAL_CTL_HIGH = 0x2c05,
	VMX_HOST_IA32_PKRS = 0x2c06,
	VMX_HOST_IA32_PKRS_HIGH = 0x2c07,

	/* host natural width state area */
	VMX_HOST_CR0 = 0x6c00,
	VMX_HOST_CR3 = 0x6c02,
	VMX_HOST_CR4 = 0x6c04,
	VMX_HOST_FS_BASE = 0x6c06,
	VMX_HOST_GS_BASE = 0x6c08,
	VMX_HOST_TR_BASE = 0x6c0a,
	VMX_HOST_GDT_BASE = 0x6c0c,
	VMX_HOST_IDT_BASE = 0x6c0e,
	VMX_HOST_IA32_SYSENTER_ESP = 0x6c10,
	VMX_HOST_IA32_SYSENTER_EIP = 0x6c12,
	VMX_HOST_RSP = 0x6c14,
	VMX_HOST_RIP = 0x6c16,

	/* guest 16bit state */
	VMX_GUEST_ES = 0x800,
	VMX_GUEST_CS = 0x802,
	VMX_GUEST_SS = 0x804,
	VMX_GUEST_DS = 0x806,
	VMX_GUEST_FS = 0x808,
	VMX_GUEST_GS = 0x80a,
	VMX_GUEST_LDTR = 0x80c,
	VMX_GUEST_TR = 0x80e,
	VMX_GUEST_INTR_STATUS = 0x810,
	VMX_GUEST_PML_INDEX = 0x812,

	/* guest 32bit state */
	VMX_GUEST_ES_LIMIT = 0x4800,
	VMX_GUEST_CS_LIMIT = 0x4802,
	VMX_GUEST_SS_LIMIT = 0x4804,
	VMX_GUEST_DS_LIMIT = 0x4806,
	VMX_GUEST_FS_LIMIT = 0x4808,
	VMX_GUEST_GS_LIMIT = 0x480a,
	VMX_GUEST_LDTR_LIMIT = 0x480c,
	VMX_GUEST_TR_LIMIT = 0x480e,
	VMX_GUEST_GDTR_LIMIT = 0x4810,
	VMX_GUEST_IDTR_LIMIT = 0x4812,
	VMX_GUEST_ES_AR = 0x4814,
	VMX_GUEST_CS_AR = 0x4816,
	VMX_GUEST_SS_AR = 0x4818,
	VMX_GUEST_DS_AR = 0x481a,
	VMX_GUEST_FS_AR = 0x481c,
	VMX_GUEST_GS_AR = 0x481e,
	VMX_GUEST_LDTR_AR = 0x4820,
	VMX_GUEST_TR_AR = 0x4822,
	VMX_GUEST_INTR_BLOCK = 0x4824,
	VMX_GUEST_ACTIVITY = 0x4826,
	VMX_GUEST_SMBASE = 0x4828,
	VMX_GUEST_IA32_SYSENTER_CS = 0x482a,
	VMX_GUEST_PREEMPT_TIMER = 0x482e,

	/* guest 64bit state */
	VMX_GUEST_VMCS_LINK_POINTER = 0x2800,
	VMX_GUEST_VMCS_LINK_POINTER_HIGH = 0x2801,
	VMX_GUEST_IA32_DEBUGCTL = 0x2802,
	VMX_GUEST_IA32_DEBUGCTL_HIGH = 0x2803,
	VMX_GUEST_IA32_PAT = 0x2804,
	VMX_GUEST_IA32_PAT_HIGH = 0x2805,
	VMX_GUEST_IA32_EFER = 0x2806,
	VMX_GUEST_IA32_EFER_HIGH = 0x2807,
	VMX_GUEST_IA32_PERF_GLOBAL_CTL = 0x2808,
	VMX_GUEST_IA32_PERF_GLOBAL_CTL_HIGH = 0x2809,
	VMX_GUEST_PDPTE0 = 0x280a,
	VMX_GUEST_PDPTE0_HIGH = 0x280b,
	VMX_GUEST_PDPTE1 = 0x280c,
	VMX_GUEST_PDPTE1_HIGH = 0x280d,
	VMX_GUEST_PDPTE2 = 0x280e,
	VMX_GUEST_PDPTE2_HIGH = 0x280f,
	VMX_GUEST_PDPTE3 = 0x2810,
	VMX_GUEST_PDPTE3_HIGH = 0x2811,
	VMX_GUEST_IA32_BNDCFGS = 0x2812,
	VMX_GUEST_IA32_BNDCFGS_HIGH = 0x2813,
	VMX_GUEST_IA32_RTIT_CTL = 0x2814,
	VMX_GUEST_IA32_RTIT_CTL_HIGH = 0x2815,
	VMX_GUEST_IA32_LBR_CTL = 0x2816,
	VMX_GUEST_IA32_LBR_CTL_HIGH = 0x2817,
	VMX_GUEST_IA32_PKRS = 0x2818,
	VMX_GUEST_IA32_PKRS_HIGH = 0x2819,

	/* guest natural state */
	VMX_GUEST_CR0 = 0x6800,
	VMX_GUEST_CR3 = 0x6802,
	VMX_GUEST_CR4 = 0x6804,
	VMX_GUEST_ES_BASE = 0x6806,
	VMX_GUEST_CS_BASE = 0x6808,
	VMX_GUEST_SS_BASE = 0x680a,
	VMX_GUEST_DS_BASE = 0x680c,
	VMX_GUEST_FS_BASE = 0x680e,
	VMX_GUEST_GS_BASE = 0x6810,
	VMX_GUEST_LDTR_BASE = 0x6812,
	VMX_GUEST_TR_BASE = 0x6814,
	VMX_GUEST_GDTR_BASE = 0x6816,
	VMX_GUEST_IDTR_BASE = 0x6818,
	VMX_GUEST_DR7 = 0x681a,
	VMX_GUEST_RSP = 0x681c,
	VMX_GUEST_RIP = 0x681e,
	VMX_GUEST_RFLAGS = 0x6820,
	VMX_GUEST_PENDING_DB_EXCEPT = 0x6822,
	VMX_GUEST_IA32_SYSENTER_ESP = 0x6824,
	VMX_GUEST_IA32_SYSENTER_EIP = 0x6826,
};

#define VMX_FIELD_ACCESS_TYPE_MASK BIT(0)
#define VMX_FIELD_ACCESS_TYPE_FULL 0
#define VMX_FIELD_ACCESS_TYPE_HIGH 1
#define VMX_FIELD_WIDTH_MASK GENMASK(14, 13)
#define VMX_FIELD_WIDTH_16 (0 << 13)
#define VMX_FIELD_WIDTH_64 (1 << 13)
#define VMX_FIELD_WIDTH_32 (2 << 13)
#define VMX_FIELD_WIDTH_NATURAL (3 << 13)

#define VMCS_FIELD_WIDTH_CHECKER(size, suffix)	       \
static inline bool vmcs_field_width_##suffix(vmcs_field field) \
{									\
	return (field & VMX_FIELD_WIDTH_MASK) == VMX_FIELD_WIDTH_##size; \
}
VMCS_FIELD_WIDTH_CHECKER(16, 16)
VMCS_FIELD_WIDTH_CHECKER(32, 32)
VMCS_FIELD_WIDTH_CHECKER(64, 64)
VMCS_FIELD_WIDTH_CHECKER(NATURAL, natural)

#define VMCS_FIELD_ACCESS_TYPE_CHECKER(type, suffix) \
static inline bool vmcs_field_access_type_##suffix(vmcs_field field) \
{ \
	return (field & VMX_FIELD_ACCESS_TYPE_MASK) == VMX_FIELD_ACCESS_TYPE_##type; \
}
VMCS_FIELD_ACCESS_TYPE_CHECKER(FULL, full)
VMCS_FIELD_ACCESS_TYPE_CHECKER(HIGH, high)

static inline unsigned long __vmcs_read(vmcs_field field)
{
	unsigned long val;

	asm_volatile_goto("mov %1, %%eax\n\t"
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

#define VMCS_READ(size) \
static inline unsigned long vmcs_read_##size(vmcs_field field) \
{ \
	WARN_ON(!vmcs_field_width_##size(field)); \
	return __vmcs_read(field); \
}
VMCS_READ(16)
VMCS_READ(32)
VMCS_READ(64)
VMCS_READ(natural)

static inline void __vmcs_write(vmcs_field field, unsigned long val)
{
	asm_volatile_goto("mov %1, %%eax\n\t"
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

#define VMCS_WRITE(size) \
static inline void vmcs_write_##size(vmcs_field field, unsigned long val)  \
{									\
	WARN_ON(!vmcs_field_width_##size(field));	   \
	return __vmcs_write(field, val);		   \
}
VMCS_WRITE(16)
VMCS_WRITE(32)
VMCS_WRITE(64)
VMCS_WRITE(natural)

/* VMX control bit definition */
#define VMX_PINBASE_EXTERNAL_INTERRUPT_EXIT BIT(0)
#define VMX_PINBASE_NMI_EXIT BIT(3)
#define VMX_EXEC_CTL_MIN		       \
	(VMX_PINBASE_EXTERNAL_INTERRUPT_EXIT | \
	 VMX_PINBASE_NMI_EXIT)

#define VMX_PROCBASE_ACTIVE_2ND_CONTROL BIT(31)
#define VMX_PROCBASE_CTL_MIN VMX_PROCBASE_ACTIVE_2ND_CONTROL

#define VMX_PROCBASE_2ND_ENABLE_EPT BIT(1)
#define VMX_PROCBASE_2ND_UNRESTRICT_GUEST BIT(7)
#define VMX_PROCBASE_2ND_CTL_MIN		\
	(VMX_PROCBASE_2ND_ENABLE_EPT |		\
	 VMX_PROCBASE_2ND_UNRESTRICT_GUEST)

#define VMX_ENTRY_LOAD_DR_DEBUGCTL BIT(2)
#define VMX_ENTRY_LOAD_PERF_GLOBAL_CTL  BIT(13)
#define VMX_ENTRY_LOAD_PAT BIT(14)
#define VMX_ENTRY_LOAD_EFER BIT(15)
#define VMX_ENTRY_LOAD_LBR_CTL BIT(21)
#define VMX_ENTRY_LOAD_PKRS BIT(22)
#define VMX_ENTRY_CTL_MIN			\
	(VMX_ENTRY_LOAD_DR_DEBUGCTL |		\
	 VMX_ENTRY_LOAD_PERF_GLOBAL_CTL |	\
	 VMX_ENTRY_LOAD_PAT |			\
	 VMX_ENTRY_LOAD_EFER |			\
	 VMX_ENTRY_LOAD_LBR_CTL |		\
	 VMX_ENTRY_LOAD_PKRS)

#define VMX_EXIT_SAVE_DR_DEBUGCTL BIT(2)
#define VMX_EXIT_IA32E BIT(9)
#define VMX_EXIT_LOAD_PERF_GLOBAL_CTL BIT(12)
#define VMX_EXIT_ACK_INTERRUPT BIT(15)
#define VMX_EXIT_SAVE_PAT BIT(18)
#define VMX_EXIT_LOAD_PAT BIT(19)
#define VMX_EXIT_SAVE_EFER BIT(20)
#define VMX_EXIT_LOAD_EFER BIT(21)
#define VMX_EXIT_LOAD_PKRS BIT(29)
#define VMX_EXIT_SAVE_PERF_GLOBAL_CTL BIT(30)
#define VMX_EXIT_CTL_MIN			\
	(VMX_EXIT_SAVE_DR_DEBUGCTL |		\
	 VMX_EXIT_IA32E |			\
	 VMX_EXIT_LOAD_PERF_GLOBAL_CTL |	\
	 VMX_EXIT_ACK_INTERRUPT |		\
	 VMX_EXIT_SAVE_PAT |			\
	 VMX_EXIT_LOAD_PAT |			\
	 VMX_EXIT_SAVE_EFER |			\
	 VMX_EXIT_LOAD_EFER |			\
	 VMX_EXIT_LOAD_PKRS |			\
	 VMX_EXIT_SAVE_PERF_GLOBAL_CTL)

#define VMX_EPT_MEM_TYPE_UC 0
#define VMX_EPT_MEM_TYPE_WB 6
#define VMX_EPT_ENABLE_AD_BITS BIT(6)
#define VMX_EPT_WALK_LENGTH_SHIFT 3

union vmx_segment_selector
{
	struct {
		unsigned int rpl:2;
		unsigned int ti:1;
		unsigned int sel:13;
	} __attribute__((packed));
	unsigned short int val;
};

union vmx_segment_ar {
	struct {
		unsigned int desc_type:4;
		unsigned int s:1;
		unsigned int dpl:2;
		unsigned int p:1;
		unsigned int reserved:4;
		unsigned int avl:1;
		unsigned int reserved_l:1;
		unsigned int db:1;
		unsigned int g:1;
		unsigned int unusable:1;
		unsigned int reserved_h:15;
	} __attribute__((packed));
	unsigned int val;
};

enum vmx_cpu_activity_state {
	VMX_CPU_ACTIVE = 0,
	VMX_CPU_HLT,
	VMX_CPU_SHUTDOWN,
	VMX_CPU_WAIT_SIPI,
};

enum vmx_cpu_interrupt_block_state {
	VMX_INTR_BLOCK_STI = BIT(0),
	VMX_INTR_BLOCK_MOV_SS = BIT(1),
	VMX_SMI_BLOCK = BIT(2),
	VMX_NMI_BLOCK = BIT(3),
};

struct vmx_segment {
	union vmx_segment_ar ar;
	union vmx_segment_selector selector;
	unsigned int base;
	unsigned int limit;
};

/* x86 accessor */
static inline u16 get_cs(void)
{
	unsigned int val;

	asm volatile("mov %%cs, %0":"=r"(val));
	return val;
}

static inline u16 get_ss(void)
{
	unsigned int val;

	asm volatile("mov %%ss, %0":"=r"(val));
	return val;
}

static inline u16 get_ds(void)
{
	unsigned int val;

	asm volatile("mov %%ds, %0":"=r"(val));
	return val;
}

static inline u16 get_es(void)
{
	unsigned int val;

	asm volatile("mov %%es, %0":"=r"(val));
	return val;
}

static inline u16 get_fs(void)
{
	unsigned int val;

	asm volatile("mov %%fs, %0":"=r"(val));
	return val;
}

static inline u16 get_gs(void)
{
	unsigned int val;

	asm volatile("mov %%gs, %0":"=r"(val));
	return val;
}

static inline u16 get_tr(void)
{
	unsigned int val;

	asm volatile("str %0":"=r"(val));
	return val;
}

static inline unsigned long get_fsbase(void)
{
	unsigned long val;

	asm volatile("rdfsbase %0":"=r"(val));
	return val;
}

static inline unsigned long get_gsbase(void)
{
	unsigned long val;

	asm volatile("rdgsbase %0":"=r"(val));
	return val;
}

struct gdt_idt_table_desc {
	unsigned short int size;
	unsigned long base;
} __attribute__((packed));

static inline void get_gdt_table_desc(struct gdt_idt_table_desc *desc)
{
	asm volatile("sgdt %0":"=m"(*desc));
}

static inline void get_idt_table_desc(struct gdt_idt_table_desc *desc)
{
	asm volatile("sidt %0":"=m"(*desc));
}

#define MSR_IA32_PKRS 0x6e1

#define X86_FLAGS_RESERVED_1 BIT(1)
#define X86_DR7_RESERVED_1 BIT(10)
#define X86_SEGMENT_TYPE_CODE_RXA 11
#define X86_SEGMENT_TYPE_DATA_RWA 3
#define X86_SEGMENT_TYPE_LDT 2
#define X86_SEGMENT_TYPE_TR_TSS_16_BUSY 3

#define X86_PAT_UC 0
#define X86_PAT_WC 1
#define X86_PAT_WT 4
#define X86_PAT_WP 5
#define X86_PAT_WB 6
#define X86_PAT_UC_MINUS 7
#define X86_PAT_DEF_VAL 0x0007040600070406ULL

#endif
