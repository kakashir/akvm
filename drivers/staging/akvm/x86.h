#ifndef __X86_H
#define __X86_H

#include <linux/types.h>

#define MSR_IA32_PKRS 0x6e1
typedef union msr_val {
	struct {
		unsigned int low;
		unsigned int high;
	};
	unsigned long val;
} msr_val_t;

#define X86_FLAGS_RESERVED_1 BIT(1)
#define X86_DR7_RESERVED_1 BIT(10)
#define X86_SEGMENT_TYPE_CODE_RXA 11
#define X86_SEGMENT_TYPE_DATA_RWA 3
#define X86_SEGMENT_TYPE_LDT 2
#define X86_SEGMENT_TYPE_TR_TSS_16_BUSY 3
#define X86_SEGMENT_TYPE_TR_TSS_32_64_BUSY 11

#define X86_PAT_UC 0
#define X86_PAT_WC 1
#define X86_PAT_WT 4
#define X86_PAT_WP 5
#define X86_PAT_WB 6
#define X86_PAT_UC_MINUS 7
#define X86_PAT_DEF_VAL 0x0007040600070406ULL

#define X86_CR0_RESERVED   (GENMASK_ULL(15, 6) | \
			    GENMASK_ULL(28, 19) | BIT_ULL(17))
#define X86_CR0_RESERVED_HIGH GENMASK_ULL(63, 32)

/* remove the bit from this if they're supported */
#define X86_CR4_RESERVED (GENMASK_ULL(63, 25) |		    \
			  X86_CR4_CET | X86_CR4_PKE |	    \
			  BIT_ULL(19) | BIT_ULL(15) |	    \
			  X86_CR4_SMXE | X86_CR4_LA57 | \
			  X86_CR4_PCE | X86_CR4_MCE)

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

union idt_entry64 {
	struct {
		unsigned int offset15_0:16;
		unsigned int selector:16;
		unsigned int ist:3;
		unsigned int zero:5;
		unsigned int type:4;
		unsigned int zero1:1;
		unsigned int dpl:2;
		unsigned int p:1;
		unsigned int offset31_16:16;
		unsigned int offset63_32;
		unsigned int reserved;
	} __attribute__((packed));
	int val[4];
};

static inline unsigned long get_idt_entry_point(union idt_entry64 * idte)
{
	return idte->offset15_0 | (idte->offset31_16 << 16) |
		((unsigned long)idte->offset63_32 << 32);
}

static inline unsigned long read_cr8(void)
{
	unsigned long val;

	asm volatile("mov %%cr8, %0\n\t":"=r"(val));
	return val;
}

static inline void write_cr8(unsigned long val)
{
	asm volatile("mov %0, %%cr8\n\t"::"r"(val));
}

static inline unsigned long read_dr(int index)
{
	unsigned long val;

	switch(index) {
	case 0:
		asm volatile("mov %%dr0, %0\n\t":"=r"(val));
		break;
	case 1:
		asm volatile("mov %%dr1, %0\n\t":"=r"(val));
		break;
	case 2:
		asm volatile("mov %%dr2, %0\n\t":"=r"(val));
		break;
	case 3:
		asm volatile("mov %%dr3, %0\n\t":"=r"(val));
		break;
	case 6:
		asm volatile("mov %%dr6, %0\n\t":"=r"(val));
		break;
	case 7:
		asm volatile("mov %%dr7, %0\n\t":"=r"(val));
		break;
	default:
		val = 0;
		WARN_ON(1);
	}

	return val;
}

static inline void write_dr(int index, unsigned long val)
{
	switch(index) {
	case 0:
		asm volatile("mov %0, %%dr0\n\t"::"r"(val));
		break;
	case 1:
		asm volatile("mov %0, %%dr1\n\t"::"r"(val));
		break;
	case 2:
		asm volatile("mov %0, %%dr2\n\t"::"r"(val));
		break;
	case 3:
		asm volatile("mov %0, %%dr3\n\t"::"r"(val));
		break;
	case 6:
		asm volatile("mov %0, %%dr6\n\t"::"r"(val));
		break;
	case 7:
		asm volatile("mov %0, %%dr7\n\t"::"r"(val));
		break;
	default:
		val = 0;
		WARN_ON(1);
	}

}


#endif
