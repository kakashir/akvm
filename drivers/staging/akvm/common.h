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
};

/* VMX feilds */
typedef unsigned int vmcs_field;
enum vmcs_filed_id {
	VMX_INSTRUCTION_ERROR = 0x4400
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

#endif
