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

struct vm_context
{
	struct vmx_region  *vmx_region;
	struct vmx_vmcs *vmcs;

	unsigned int pinbase_ctl;
	unsigned int procbase_ctl;
	unsigned int procbase_2nd_ctl;
	unsigned int entry_ctl;
	unsigned int exit_ctl;
};

/* VMX feilds */
typedef unsigned int vmcs_field;
enum vmcs_filed_id {
	VMX_INSTRUCTION_ERROR = 0x4400,

	VMX_PINBASE_CTL = 0x4000,
	VMX_PROCBASE_CTL = 0x4002,
	VMX_PROCBASE_2ND_CTL = 0x401e,
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

#endif
