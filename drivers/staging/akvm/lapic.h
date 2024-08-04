#ifndef __AKVM_LAPIC_H__
#define __AKVM_LAPIC_H__

#include <linux/types.h>
#include "common.h"

#define X86_LAPIC_ID 0x20
#define X86_LAPIC_VERSION 0x30
#define X86_LAPIC_TPR 0x80
#define X86_LAPIC_PPR 0xa0
#define X86_LAPIC_EOI 0xb0
#define X86_LAPIC_LDR 0xd0
#define X86_LAPIC_DFR 0xe0
#define X86_LAPIC_SIV 0xf0
#define X86_LAPIC_ISR 0x100
#define X86_LAPIC_TMR 0x180
#define X86_LAPIC_IRR 0x200
#define X86_LAPIC_ESR 0x280
#define X86_LAPIC_LVT_CMCI 0x2f0
#define X86_LAPIC_ICR 0x300
#define X86_LAPIC_ICR_HIGH 0x310
#define X86_LAPIC_LVT_TIMER 0x320
#define X86_LAPIC_LVT_THERMAL 0x330
#define X86_LAPIC_LVT_PMC 0x340
#define X86_LAPIC_LVT_LINT0 0x350
#define X86_LAPIC_LVT_LINT1 0x360
#define X86_LAPIC_LVT_ERROR 0x370
#define X86_LAPIC_TIMER_ICR 0x380
#define X86_LAPIC_TIMER_CCR 0x390
#define X86_LAPIC_TIMER_DCR 0x3e0

#define X86_LAPIC_LVTT_MASK BIT(16)
#define X86_LAPIC_LVTT_COUNT 7
#define X86_LAPIC_VERSION_SUPPRESS_EOI_BROADCAST BIT(24)
#define X86_LAPIC_VERSION_VER 0x10

struct vcpu_context;
struct akvm_lapic {
	void *apic_reg;
	struct vcpu_context *vcpu;
};

int akvm_create_lapic(struct akvm_lapic *lapic,
		       struct vcpu_context *vcpu);
void akvm_destroy_lapic(struct akvm_lapic *lapic);
u32 akvm_lapic_read_reg(struct akvm_lapic *lapic, u32 reg);
void akvm_lapic_write_reg(struct akvm_lapic *lapic, u32 reg, u32 val);

#endif
