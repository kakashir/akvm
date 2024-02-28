#ifndef __VMX_H
#define __VMX_H

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/mm.h>

#include "common.h"
#include "x86.h"

struct vmx_capability {
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

int probe_vmx_basic_info(struct vmx_capability *info);

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

static inline bool vmx_ept_invept_supported(struct vmx_capability *vmx_cap)
{
	return !!(vmx_cap->msr_ept_vpid & BIT(20));
}

static inline bool vmx_ept_invept_single_context(struct vmx_capability *vmx_cap)
{
	return !!(vmx_cap->msr_ept_vpid & BIT(25));
}

static inline bool vmx_ept_invept_all_context(struct vmx_capability *vmx_cap)
{
	return !!(vmx_cap->msr_ept_vpid & BIT(26));
}

static inline gpa vmx_ept_max_addr(struct vmx_capability *vmx_cap)
{
	return 1UL << ((vmx_ept_level(vmx_cap) == 4) ? 48 : 52);
}

struct vmx_region {
	u32 revision:31;
};

void prepare_vmx_region(struct vmx_region *region,
			unsigned int size,
			unsigned int revision);

int vmx_on(struct vmx_region *vmx_region);
void vmx_off(void);

/* VMCS only has valid head definition */
struct vmx_vmcs {
	u32 revision:31;
	u32 shadow:1;
	u32 abort;
};

void prepare_vmcs(struct vmx_vmcs *vmcs, unsigned int size,
		  unsigned int revision);
int vmcs_load(struct vmx_vmcs *vmcs);
void vmcs_clear(struct vmx_vmcs *vmcs);

union vmx_exit_reason {
	struct {
		unsigned int reason:16;
		unsigned int reserved:11;
		unsigned int enclave:1;
		unsigned int mtf:1;
		unsigned int vmx_root:1;
		unsigned int reserved1:1;
		unsigned int failed:1;
	} __attribute__((packed));
	int val;
};
#define VMX_EXIT_EXCEP_NMI  0
#define VMX_EXIT_INTR  1
#define VMX_EXIT_VMCALL 18
#define VMX_EXIT_CR 28
#define VMX_EXIT_RDMSR 31
#define VMX_EXIT_WRMSR 32
#define VMX_EXIT_EPT_VIOLATION 48
#define VMX_EXIT_PREEMPT_TIMER 52
#define VMX_EXIT_MAX_NUMBER 78

union vmx_intr_info {
	struct {
		unsigned int vector:8;
		unsigned int type:3;
		unsigned int error_code:1;
		unsigned int iret_nmi_block:1;
		unsigned int reserved:18;
		unsigned int valid:1;
	} __attribute__((packed));
	int val;
};
#define VMX_INTR_TYPE_EXTERNAL 0
#define VMX_INTR_TYPE_NMI 2
#define VMX_INTR_HW_EXCEP 3
#define VMX_INTR_PRIV_SW_EXCEP 5
#define VMX_INTR_SW_EXCEP 6

#define VMCS_MEM_TYPE_UC 0
#define VMCS_MEM_TYPE_WB 6

/* VMX feilds */
typedef unsigned int vmcs_field;
enum vmcs_filed_id {
	VMX_INSTRUCTION_ERROR = 0x4400,
	VMX_EXIT_REASON = 0x4402,
	VMX_EXIT_QUALIFICATION = 0x6400,
	VMX_EXIT_INTR_INFO = 0x4404,
	VMX_EXIT_INTR_ERROR_CODE = 0x4406,
	VMX_EXIT_GPA = 0x2400,
	VMX_EXIT_GPA_HIGH = 0x2401,
	VMX_EXIT_INSTRUCTION_LENGTH = 0x440c,
	VMX_PINBASE_CTL = 0x4000,
	VMX_PROCBASE_CTL = 0x4002,
	VMX_PROCBASE_2ND_CTL = 0x401e,
	VMX_EPTP_POINTER = 0x201a,
	VMX_ENTRY_CTL = 0x4012,
	VMX_EXIT_CTL = 0x400c,
	VMX_CR0_HOST_MASK = 0x6000,
	VMX_CR0_READ_SHADOW = 0x6004,
	VMX_CR4_HOST_MASK = 0x6002,
	VMX_CR4_READ_SHADOW = 0x6006,
	VMX_MSR_BITMAP = 0x2004,
	VMX_MSR_BITMAP_HIGH = 0x2005,
	VMX_ENTRY_EVENT_INFO = 0x4016,
	VMX_ENTRY_EVENT_ERROR_CODE = 0x4018,
	VMX_ENTRY_INSTRUCTION_LEN = 0x401a,
	VMX_EXIT_VECTORING_INFO = 0x4408,
	VMX_EXIT_VECTORING_ERROR_CODE = 0x440a,
	VMX_VPID = 0x0,

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

unsigned long __vmcs_read(vmcs_field field);
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

void __vmcs_write(vmcs_field field, unsigned long val);
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

static inline int __invept(unsigned long ept_root)
{
	unsigned long type = ept_root ? 1 : 2;
	unsigned long inv_desc[2] = {ept_root, 0};

	asm_volatile_goto("1: invept %0, %1\n\t"
			  "jz %l[fail]\n\t"
			  "jc %l[failinvalid]\n\t"
			  _ASM_EXTABLE(1b, %l[fault])
			  ::"m"(inv_desc), "q"(type)
			  ::fault, fail, failinvalid);
	return 0;
 fault:
	pr_err("%s() fault: ept_root:0x%lx\n", __func__, inv_desc[0]);
	return -EINVAL;
 fail:
	pr_err("%s() VMfailed: ept_root:0x%lx\n", __func__, inv_desc[0]);
	return -EINVAL;
 failinvalid:
	pr_err("%s() VMfailedInvalid: ept_root:0x%lx\n",
	       __func__, inv_desc[0]);
	return -EINVAL;
}

int invept(unsigned long ept_root, struct vmx_capability *vmx_cap);

/* VMX control bit definition */
#define VMX_PINBASE_EXTERNAL_INTERRUPT_EXIT BIT(0)
#define VMX_PINBASE_NMI_EXIT BIT(3)
#define VMX_PINBASE_PREEMPT_TIMER BIT(6)

#define VMX_PROCBASE_ACTIVE_3RD_CONTROL BIT(17)
#define VMX_PROCBASE_UNCOND_IO_EXIT BIT(24)
#define VMX_PROCBASE_MSR_BITMAP BIT(28)
#define VMX_PROCBASE_ACTIVE_2ND_CONTROL BIT(31)

#define VMX_PROCBASE_2ND_ENABLE_EPT BIT(1)
#define VMX_PROCBASE_2ND_UNRESTRICT_GUEST BIT(7)
#define VMX_PROCBASE_2ND_VPID BIT(5)

#define VMX_ENTRY_LOAD_DR_DEBUGCTL BIT(2)
#define VMX_ENTRY_IA32E BIT(9)
#define VMX_ENTRY_LOAD_PERF_GLOBAL_CTL  BIT(13)
#define VMX_ENTRY_LOAD_PAT BIT(14)
#define VMX_ENTRY_LOAD_EFER BIT(15)
#define VMX_ENTRY_LOAD_LBR_CTL BIT(21)
#define VMX_ENTRY_LOAD_PKRS BIT(22)

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

#define VMX_EPT_MEM_TYPE_UC 0
#define VMX_EPT_MEM_TYPE_WB 6
#define VMX_EPT_ENABLE_AD_BITS BIT(6)
#define VMX_EPT_WALK_LENGTH_SHIFT 3

static inline bool vmx_cap_unrestrict_guest(unsigned int procbased,
					    unsigned int procbased_2nd)
{
	if (!(procbased & VMX_PROCBASE_ACTIVE_2ND_CONTROL))
		return false;
	if (!(procbased_2nd & VMX_PROCBASE_2ND_UNRESTRICT_GUEST))
		return false;
	if (!(procbased_2nd & VMX_PROCBASE_2ND_ENABLE_EPT))
		return false;
	return true;
}


union vmx_segment_selector {
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

static inline void vmx_get_ctl_msr_fix_bit(int msr,
					   u32 *ctl_fix_0, u32 *ctl_fix_1)
{
	u32 low, high;

	rdmsr(msr, low, high);

	*ctl_fix_0 = ~high;
	*ctl_fix_1 = low;
}

static inline void vmx_get_ctl_msr_fix_bit2(int msr,
					    u64 *ctl_fix_0, u64 *ctl_fix_1)
{
	u64 val;

	rdmsrl(msr, val);

	*ctl_fix_0 = ~val;
	*ctl_fix_1 = 0;
}

static inline void vmx_get_cr_fix_bit(int msr_fixed0, int msr_fixed1,
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

#define VMX_EPT_PTE_PERM_READ  BIT_ULL(0)
#define VMX_EPT_PTE_PERM_WRITE BIT_ULL(1)
#define VMX_EPT_PTE_PERM_EXE BIT_ULL(2)
#define VMX_EPT_PTE_LARGE_PAGE BIT_ULL(7)
#define VMX_EPT_PTE_MEM_TYPE_WB (6ULL << 3)
#define VMX_EPT_PTE_MEM_TYPE_UC (0ULL << 3)
#define VMX_EPT_PTE_PAGE_SHIFT 12

#define VMX_EPT_PTE_PRESENT (VMX_EPT_PTE_PERM_READ | \
			     VMX_EPT_PTE_PERM_WRITE | \
			     VMX_EPT_PTE_PERM_EXE)

static inline bool vmx_ept_pte_present(unsigned long val)
{
	return !!(val & VMX_EPT_PTE_PRESENT);
}

static inline bool vmx_ept_pte_large_page(unsigned long val)
{
	return !!(val & VMX_EPT_PTE_LARGE_PAGE);
}

bool vmx_inject_event_need_set_flags_rf(int vector);
bool vmx_need_vmentry_instruction_len(enum x86_event_type type);
void vmx_inject_event(int vector, enum x86_event_type type,
		      bool has_error_code, unsigned long error_code,
		      int instruction_len);


#endif
