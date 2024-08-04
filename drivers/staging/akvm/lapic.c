#include "lapic.h"
#include "x86.h"
#include "vcpu.h"

#define LAPIC_VERSION (X86_LAPIC_VERSION_VER	\
		       | ((X86_LAPIC_LVTT_COUNT - 1) << 16)	\
		       | X86_LAPIC_VERSION_SUPPRESS_EOI_BROADCAST)

static void __lapic_write_reg(struct akvm_lapic *lapic, u32 reg, u32 val)
{
	*((u32*)(lapic->apic_reg + reg)) = val;
}

static u32 __lapic_read_reg(struct akvm_lapic *lapic, u32 reg)
{
	return *((u32*)(lapic->apic_reg + reg));
}

static void reset_lapic_init_state(struct akvm_lapic *lapic, bool x2apic)
{
	u32 apic_id;

	memset(lapic->apic_reg, 0, PAGE_SIZE);

	__lapic_write_reg(lapic, X86_LAPIC_VERSION, LAPIC_VERSION);

	if (x2apic)
		apic_id = lapic->vcpu->index;
	else
		apic_id = lapic->vcpu->index << 24;
	__lapic_write_reg(lapic, X86_LAPIC_ID, apic_id);

	__lapic_write_reg(lapic, X86_LAPIC_DFR, 0xFFFFFFFF);

	__lapic_write_reg(lapic, X86_LAPIC_LVT_CMCI, X86_LAPIC_LVTT_MASK);
	__lapic_write_reg(lapic, X86_LAPIC_LVT_TIMER, X86_LAPIC_LVTT_MASK);
	__lapic_write_reg(lapic, X86_LAPIC_LVT_THERMAL, X86_LAPIC_LVTT_MASK);
	__lapic_write_reg(lapic, X86_LAPIC_LVT_PMC, X86_LAPIC_LVTT_MASK);
	__lapic_write_reg(lapic, X86_LAPIC_LVT_LINT0, X86_LAPIC_LVTT_MASK);
	__lapic_write_reg(lapic, X86_LAPIC_LVT_LINT1, X86_LAPIC_LVTT_MASK);
	__lapic_write_reg(lapic, X86_LAPIC_LVT_ERROR, X86_LAPIC_LVTT_MASK);

	__lapic_write_reg(lapic, X86_LAPIC_SIV, 0xff);
}

u32 akvm_lapic_read_reg(struct akvm_lapic *lapic, u32 reg)
{
	return __lapic_read_reg(lapic, reg);
}

void akvm_lapic_write_reg(struct akvm_lapic *lapic, u32 reg, u32 val)
{
	return __lapic_write_reg(lapic, reg, val);
}

int akvm_create_lapic(struct akvm_lapic *lapic, struct vcpu_context *vcpu)
{
	lapic->apic_reg =
		(void*)__get_free_page(GFP_KERNEL_ACCOUNT);
	if (!lapic->apic_reg)
		return -ENOMEM;

	lapic->vcpu = vcpu;
	reset_lapic_init_state(lapic, false);

	return 0;
}

void akvm_destroy_lapic(struct akvm_lapic *lapic)
{
	free_page((unsigned long)lapic->apic_reg);
}
