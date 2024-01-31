#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

#include <uapi/linux/akvm.h>

#include <asm/msr-index.h>
#include <asm/cpu_entry_area.h>
#include <asm/idtentry.h>

#include "common.h"
#include "x86.h"
#include "vmx.h"

#define VMX_PINBASE_CTL_MIN		       \
	(VMX_PINBASE_EXTERNAL_INTERRUPT_EXIT | \
	 VMX_PINBASE_NMI_EXIT)

#define VMX_PROCBASE_2ND_CTL_MIN		\
	(VMX_PROCBASE_2ND_ENABLE_EPT |		\
	 VMX_PROCBASE_2ND_UNRESTRICT_GUEST)

#define VMX_ENTRY_CTL_MIN			\
	(VMX_ENTRY_LOAD_DR_DEBUGCTL |		\
	 VMX_ENTRY_LOAD_PERF_GLOBAL_CTL |	\
	 VMX_ENTRY_LOAD_PAT |			\
	 VMX_ENTRY_LOAD_EFER |			\
	 VMX_ENTRY_LOAD_LBR_CTL |		\
	 VMX_ENTRY_LOAD_PKRS)

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

static struct vmx_capability vmx_capability;
static struct vm_context vm_context;

static void free_vmcs(struct vm_context *vm)
{
	/* kfree takes care NULL ptr */
	kfree(vm->vmx_region);
	kfree(vm->vmcs);
	free_page(vm->ept_root);
}

static int alloc_vmcs(struct vm_context *vm)
{
	size_t size = vmx_region_size(&vmx_capability);

	vm->vmx_region = kmalloc(size, GFP_KERNEL_ACCOUNT);
	if (!vm->vmx_region) {
		pr_err("failed to alloc vmxon region\n");
		return -ENOMEM;
	}

	vm->vmcs = kmalloc(size, GFP_KERNEL_ACCOUNT);
	if (!vm->vmcs) {
		pr_err("failed to alloc vmcs\n");
		goto failed_free;
	}

	vm->ept_root = __get_free_page(GFP_KERNEL);
	if (!vm->ept_root) {
		pr_err("failed to alloc ept root\n");
		goto failed_free;
	}
	return 0;

 failed_free:
	free_vmcs(vm);
	return -ENOMEM;
}

static int setup_vmcs_control(struct vm_context *vm,
			      struct vmx_capability *cap)
{
	unsigned int vmx_pinbase = VMX_PINBASE_CTL_MIN;
	unsigned int vmx_procbase = VMX_PROCBASE_CTL_MIN;
	unsigned int vmx_procbase_2nd = VMX_PROCBASE_2ND_CTL_MIN;
	unsigned int vmx_entry = VMX_ENTRY_CTL_MIN;
	unsigned int vmx_exit  = VMX_EXIT_CTL_MIN;

	vmx_adjust_ctl_bit(vmx_pinbase,
			   cap->pin_based_exec_fixed_0,
			   cap->pin_based_exec_fixed_1);
	if (!vmx_check_ctl_bit(vmx_pinbase, VMX_PINBASE_CTL_MIN)) {
		pr_err("unsupported vmx pinbase:0x%x\n", vmx_pinbase);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_procbase,
			   cap->proc_based_exec_fixed0,
			   cap->proc_based_exec_fixed1);
	if (!vmx_check_ctl_bit(vmx_procbase, VMX_PROCBASE_CTL_MIN)) {
		pr_err("unsupported vmx procbase:0x%x\n", vmx_procbase);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_procbase_2nd,
			   cap->proc_based_2nd_exec_fixed0,
			   cap->proc_based_2nd_exec_fixed1);
	if (!vmx_check_ctl_bit(vmx_procbase_2nd, VMX_PROCBASE_2ND_CTL_MIN)) {
		pr_err("unsupported vmx procbase 2nd:0x%x\n", vmx_procbase_2nd);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_entry,
			   cap->vmentry_fixed0, cap->vmentry_fixed1);
	if (!vmx_check_ctl_bit(vmx_entry, VMX_ENTRY_CTL_MIN)) {
		pr_err("unsupported vmx entry:0x%x\n", vmx_entry);
		return -EINVAL;
	}

	vmx_adjust_ctl_bit(vmx_exit,
			   cap->vmexit_fixed0, cap->vmexit_fixed1);
	if (!vmx_check_ctl_bit(vmx_exit, VMX_EXIT_CTL_MIN)) {
		pr_err("unsupported vmx exit:0x%x\n", vmx_exit);
		return -EINVAL;
	}

	vmcs_write_32(VMX_PINBASE_CTL, vmx_pinbase);
	vmcs_write_32(VMX_PROCBASE_CTL, vmx_procbase);
	vmcs_write_32(VMX_PROCBASE_2ND_CTL, vmx_procbase_2nd);
	vmcs_write_32(VMX_ENTRY_CTL, vmx_entry);
	vmcs_write_32(VMX_EXIT_CTL, vmx_exit);

	vm->pinbase_ctl = vmx_pinbase;
	vm->procbase_ctl = vmx_procbase;
	vm->procbase_2nd_ctl = vmx_procbase_2nd;
	vm->entry_ctl = vmx_entry;
	vm->exit_ctl = vmx_exit;

	return 0;
}

static int setup_vmcs_host_state(struct vm_context *vm)
{
	extern void akvm_vmx_vmexit(void);

	union {
		struct {
			unsigned int low;
			unsigned int high;
		};
		unsigned long val;
	} msr_val;

	struct gdt_idt_table_desc gdt_idt_desc;
	int cpu = smp_processor_id();

	/*
	  CR0 CR3 CR4
	  RSP RIP are handled before vmlaunch/vmresume
	  CS SS DS ES FS GS TR selector
	  FS GS TR GDTR IDTR Base

	  Question:
		GDT/IDT's limit will be set to 0xffff by hardware
		Does this become kind of issue now?

	  IA32_SYSENTER_CS
	  IA32_SYSENTER_ESP
	  IA32_SYSENTER_EIP
	  IA32_PERF_GLOBAL_CTRL
	  IA32_PAT
	  IA32_EFER
	  IA32_PKRS
	  IA32_S_CET (not need now)
	  IA32_INETRRUPT_SSP_TABLE_ADDR (not need now)
	 */
	vmcs_write_natural(VMX_HOST_CR0, read_cr0());
	vmcs_write_natural(VMX_HOST_CR3, __read_cr3());
	vmcs_write_natural(VMX_HOST_CR4, __read_cr4());

	vmcs_write_natural(VMX_HOST_RIP, (unsigned long)akvm_vmx_vmexit);

	vmcs_write_16(VMX_HOST_CS, get_cs());
	vmcs_write_16(VMX_HOST_SS, get_ss());
	vmcs_write_16(VMX_HOST_DS, get_ds());
	vmcs_write_16(VMX_HOST_ES, get_es());
	vmcs_write_16(VMX_HOST_FS, get_fs());
	vmcs_write_16(VMX_HOST_GS, get_gs());
	vmcs_write_16(VMX_HOST_TR, get_tr());

	vmcs_write_natural(VMX_HOST_FS_BASE, get_fsbase());
	pr_info("fsbase: 0x%lx\n", get_fsbase());

	vmcs_write_natural(VMX_HOST_GS_BASE, get_gsbase());
	pr_info("gsbase: 0x%lx\n", get_gsbase());

	vmcs_write_natural(VMX_HOST_TR_BASE,
			   (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
	pr_info("tr_base: 0x%lx\n", (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);

	get_gdt_table_desc(&gdt_idt_desc);
	vmcs_write_natural(VMX_HOST_GDT_BASE, gdt_idt_desc.base);
	pr_info("gdt: base:0x%lx size:%d\n",
		gdt_idt_desc.base, (int)gdt_idt_desc.size);

	get_idt_table_desc(&gdt_idt_desc);
	vmcs_write_natural(VMX_HOST_IDT_BASE, gdt_idt_desc.base);
	pr_info("idt: base:0x%lx size:%d\n",
		gdt_idt_desc.base, (int)gdt_idt_desc.size);

	rdmsr(MSR_IA32_SYSENTER_CS, msr_val.low, msr_val.high);
	vmcs_write_32(VMX_HOST_IA32_SYSENTER_CS, msr_val.low);
	pr_info("sysenter_cs: 0x%x\n", msr_val.low);

	rdmsr(MSR_IA32_SYSENTER_ESP, msr_val.low, msr_val.high);
	vmcs_write_natural(VMX_HOST_IA32_SYSENTER_ESP, msr_val.val);
	pr_info("sysenter_esp: 0x%lx\n", msr_val.val);

	rdmsr(MSR_IA32_SYSENTER_EIP, msr_val.low, msr_val.high);
	vmcs_write_natural(VMX_HOST_IA32_SYSENTER_EIP, msr_val.val);
	pr_info("sysenter_eip: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_PERF_GLOBAL_CTL, msr_val.val);
	pr_info("perf_global_ctl: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_IA32_CR_PAT, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_PAT, msr_val.val);
	pr_info("ia32_pat: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_EFER, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_EFER, msr_val.val);
	pr_info("ia32_efer: 0x%lx\n", msr_val.val);

	rdmsrl(MSR_IA32_PKRS, msr_val.val);
	vmcs_write_64(VMX_HOST_IA32_PKRS, msr_val.val);
	pr_info("ia32_pkrs: 0x%lx\n", msr_val.val);

	return 0;
}

static void setup_ept_root(struct vm_context *vm, struct vmx_capability *cap)
{
	unsigned long ept_val;

	if (!vm->ept_root) {
		pr_info("ept_root: skip due to no ept_root page\n");
		return;
	}

	WARN_ON(!vmx_ept_mem_type_wb(cap));

	ept_val = __pa(vm->ept_root) & PAGE_MASK;
	ept_val |= VMX_EPT_MEM_TYPE_WB;
	ept_val |= (vmx_ept_level(cap) - 1) << VMX_EPT_WALK_LENGTH_SHIFT;
	if (vmx_ept_ad_bit(cap))
		ept_val |= VMX_EPT_ENABLE_AD_BITS;

	vmcs_write_64(VMX_EPTP_POINTER, ept_val);
	pr_info("ept_root: 0x%lx\n", ept_val);
}

static int setup_vmcs_guest_state(struct vm_context *vm,
				  struct vmx_capability *cap)
{
	unsigned long val;
	struct vmx_segment code_seg = {0};
	struct vmx_segment data_seg = {0};
	struct vmx_segment ldtr_seg = {0};
	struct vmx_segment tr_seg = {0};

	/*
	  CR0 CR3 CR4
	  DR7
	  RSP RIP RFLAGS
	  CS SS DS ES FS GS LDTR TR:
		selector
		base
		segment limit(32 bit) in byte
		access right(32 bit)
	  GDTR IDTR
		base
		limit
	  MSR_IA32_DEBUGCTL
	  IA32_SYSENTER_CS
	  IA32_SYSENTER_ESP
	  IA32_SYSENTER_RIP
	  IA32_PERF_GLOBAL_CTRL
	  IA32_PAT
	  IA32_EFER
	  IA32_BNDCFGS
	  IA32_RTIT_CTL
	  IA32_LBR_CTL
	  IA32_S_CET (not need now)
	  IA32_INTERRUPT_SSP_TABLE_ADDR (not need now)
	  IA32_PKRS

	  Non-registers:
		Activity State
		Interruptibility state
		Pending debug exception
		VMCS link pointer
		VMX preempt timer value
		PDPTEs
		Guest interrupt state
			RVI
			SVI
		PML Index
	 */

	val = cap->cr0_fixed1;
	if ((vm->procbase_2nd_ctl & VMX_PROCBASE_2ND_UNRESTRICT_GUEST) &&
	    (vm->procbase_2nd_ctl & VMX_PROCBASE_2ND_ENABLE_EPT) &&
	    (vm->procbase_ctl & VMX_PROCBASE_ACTIVE_2ND_CONTROL))
		val &= ~(X86_CR0_PG | X86_CR0_PE);
	vmcs_write_natural(VMX_GUEST_CR0, val);
	pr_info("guest cr0: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_CR3, val);
	pr_info("guest cr3: 0x%lx\n", val);

	val = cap->cr4_fixed1;
	vmcs_write_natural(VMX_GUEST_CR4, val);
	pr_info("guest cr4: 0x%lx\n", val);

	val = X86_DR7_RESERVED_1;
	vmcs_write_natural(VMX_GUEST_DR7, val);
	pr_info("guest dr7: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_RIP, val);
	pr_info("guest rip: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_RSP, val);
	pr_info("guest rsp: 0x%lx\n", val);

	val = X86_FLAGS_RESERVED_1;
	vmcs_write_natural(VMX_GUEST_RFLAGS, val);
	pr_info("guest rflags: 0x%lx\n", val);

	/*
	  CS SS DS ES FS GS LDTR TR:
		selector
		base
		segment limit(32 bit) in byte
		access right(32 bit)
	 */
	data_seg.base = 0;
	data_seg.limit= 0xffff;
	data_seg.selector.val = 0;
	data_seg.ar.desc_type = X86_SEGMENT_TYPE_DATA_RWA;
	data_seg.ar.s = true;
	data_seg.ar.dpl = 0;
	data_seg.ar.p = true;
	data_seg.ar.db = 0;
	data_seg.ar.g = 0;
	data_seg.ar.unusable = false;
	pr_info("guest data seg: base:0x%x limit:0x%x ar:0x%x\n",
		data_seg.base, data_seg.limit, data_seg.ar.val);
	vmcs_write_16(VMX_GUEST_ES, data_seg.selector.val);
	vmcs_write_16(VMX_GUEST_SS, data_seg.selector.val);
	vmcs_write_16(VMX_GUEST_DS, data_seg.selector.val);
	vmcs_write_16(VMX_GUEST_FS, data_seg.selector.val);
	vmcs_write_16(VMX_GUEST_GS, data_seg.selector.val);
	vmcs_write_natural(VMX_GUEST_ES_BASE, data_seg.base);
	vmcs_write_natural(VMX_GUEST_SS_BASE, data_seg.base);
	vmcs_write_natural(VMX_GUEST_DS_BASE, data_seg.base);
	vmcs_write_natural(VMX_GUEST_FS_BASE, data_seg.base);
	vmcs_write_natural(VMX_GUEST_GS_BASE, data_seg.base);
	vmcs_write_32(VMX_GUEST_ES_LIMIT, data_seg.limit);
	vmcs_write_32(VMX_GUEST_SS_LIMIT, data_seg.limit);
	vmcs_write_32(VMX_GUEST_DS_LIMIT, data_seg.limit);
	vmcs_write_32(VMX_GUEST_FS_LIMIT, data_seg.limit);
	vmcs_write_32(VMX_GUEST_GS_LIMIT, data_seg.limit);
	vmcs_write_32(VMX_GUEST_ES_AR, data_seg.ar.val);
	vmcs_write_32(VMX_GUEST_SS_AR, data_seg.ar.val);
	vmcs_write_32(VMX_GUEST_DS_AR, data_seg.ar.val);
	vmcs_write_32(VMX_GUEST_FS_AR, data_seg.ar.val);
	vmcs_write_32(VMX_GUEST_GS_AR, data_seg.ar.val);

	code_seg.base = 0;
	code_seg.limit= 0xffff;
	code_seg.selector.val = 0;
	code_seg.ar.desc_type = X86_SEGMENT_TYPE_CODE_RXA;
	code_seg.ar.s = true;
	code_seg.ar.dpl = 0;
	code_seg.ar.p = true;
	code_seg.ar.db = 0;
	code_seg.ar.g = 0;
	code_seg.ar.unusable = false;
	pr_info("guest code seg: base:0x%x limit:0x%x ar:0x%x\n",
		code_seg.base, code_seg.limit, code_seg.ar.val);
	vmcs_write_16(VMX_GUEST_CS, code_seg.selector.val);
	vmcs_write_natural(VMX_GUEST_CS_BASE, code_seg.base);
	vmcs_write_32(VMX_GUEST_CS_LIMIT, code_seg.limit);
	vmcs_write_32(VMX_GUEST_CS_AR, code_seg.ar.val);

	ldtr_seg.base = 0;
	ldtr_seg.limit= 0xffff;
	ldtr_seg.selector.val = 0;
	ldtr_seg.ar.unusable = true;
	pr_info("guest ldtr seg: base:0x%x limit:0x%x ar:0x%x\n",
		ldtr_seg.base, ldtr_seg.limit, ldtr_seg.ar.val);
	vmcs_write_16(VMX_GUEST_LDTR, ldtr_seg.selector.val);
	vmcs_write_natural(VMX_GUEST_LDTR_BASE, ldtr_seg.base);
	vmcs_write_32(VMX_GUEST_LDTR_LIMIT, ldtr_seg.limit);
	vmcs_write_32(VMX_GUEST_LDTR_AR, ldtr_seg.ar.val);

	tr_seg.base = 0;
	tr_seg.limit= 0xffff;
	tr_seg.selector.val = 0;
	tr_seg.ar.desc_type = X86_SEGMENT_TYPE_TR_TSS_16_BUSY;
	tr_seg.ar.s = false;
	tr_seg.ar.dpl = 0;
	tr_seg.ar.p = true;
	tr_seg.ar.db = 0;
	tr_seg.ar.g = 0;
	tr_seg.ar.unusable = false;
	pr_info("guest tr seg: base:0x%x limit:0x%x ar:0x%x\n",
		tr_seg.base, tr_seg.limit, tr_seg.ar.val);
	vmcs_write_16(VMX_GUEST_TR, tr_seg.selector.val);
	vmcs_write_natural(VMX_GUEST_TR_BASE, tr_seg.base);
	vmcs_write_32(VMX_GUEST_TR_LIMIT, tr_seg.limit);
	vmcs_write_32(VMX_GUEST_TR_AR, tr_seg.ar.val);

	/*
	  GDTR IDTR
		base
		limit
	 */
	val = 0;
	vmcs_write_natural(VMX_GUEST_GDTR_BASE, val);
	vmcs_write_32(VMX_GUEST_GDTR_LIMIT, val);
	pr_info("guest gdt: base:0x%lx limit:0x%lx\n", val, val);
	vmcs_write_natural(VMX_GUEST_IDTR_BASE, val);
	vmcs_write_32(VMX_GUEST_IDTR_LIMIT, val);
	pr_info("guest idt: base:0x%lx limit:0x%lx\n", val, val);

	/*
	  MSR_IA32_DEBUGCTL
	  IA32_SYSENTER_CS
	  IA32_SYSENTER_ESP
	  IA32_SYSENTER_RIP
	  IA32_PERF_GLOBAL_CTRL
	  IA32_PAT
	  IA32_EFER
	  IA32_BNDCFGS
	  IA32_RTIT_CTL
	  IA32_LBR_CTL
	  IA32_S_CET (not need now)
	  IA32_INTERRUPT_SSP_TABLE_ADDR (not need now)
	  IA32_PKRS
	 */
	vmcs_write_64(VMX_GUEST_IA32_DEBUGCTL, 0);
	vmcs_write_32(VMX_GUEST_IA32_SYSENTER_CS, 0);
	vmcs_write_natural(VMX_GUEST_IA32_SYSENTER_ESP, 0);
	vmcs_write_natural(VMX_GUEST_IA32_SYSENTER_EIP, 0);
	vmcs_write_64(VMX_GUEST_IA32_PERF_GLOBAL_CTL, 0);
	vmcs_write_64(VMX_GUEST_IA32_PAT, X86_PAT_DEF_VAL);
	vmcs_write_64(VMX_GUEST_IA32_EFER, 0);
	/* vmcs_write_64(VMX_GUEST_IA32_BNDCFGS, 0); */
	vmcs_write_64(VMX_GUEST_IA32_RTIT_CTL, 0);
	vmcs_write_64(VMX_GUEST_IA32_LBR_CTL, 0);
	vmcs_write_64(VMX_GUEST_IA32_PKRS, 0);

	/*
	  Non-registers:
		Activity State
		Interruptibility state
		Pending debug exception
		VMCS link pointer
		VMX preempt timer value
		PDPTEs
		Guest interrupt state
			RVI
			SVI
		PML Index
	 */
	val = VMX_CPU_ACTIVE;
	vmcs_write_32(VMX_GUEST_ACTIVITY, val);
	pr_info("guest activity: 0x%lx\n", val);

	val = 0;
	vmcs_write_32(VMX_GUEST_INTR_BLOCK, val);
	pr_info("guest intr block: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_PENDING_DB_EXCEPT, val);
	pr_info("guest pending #DB: 0x%lx\n", val);

	val = -1ULL;
	vmcs_write_64(VMX_GUEST_VMCS_LINK_POINTER, val);
	pr_info("guest vmcs link pointer: 0x%lx\n", val);
	return 0;
}

static void save_host_state(struct vm_host_state *state)
{
	int i;

	state->cr8 = read_cr8();

	for (i = 0; i < 8; ++i) {
		if (i == 4 || i == 5)
			continue;
		state->dr[i] = read_dr(i);
	}

	rdmsrl(MSR_IA32_DEBUGCTLMSR, state->msr_debugctl);
	rdmsrl(MSR_IA32_RTIT_CTL, state->msr_rtit_ctl);
	rdmsrl(MSR_ARCH_LBR_CTL, state->msr_lbr_ctl);
}

static void load_host_state(struct vm_host_state *state)
{
	int i;

	write_cr8(state->cr8);

	for (i = 0; i < 8; ++i) {
		if (i == 4 || i == 5)
			continue;
		write_dr(i, state->dr[i]);
	}

	wrmsrl(MSR_IA32_DEBUGCTLMSR, state->msr_debugctl);
	wrmsrl(MSR_IA32_RTIT_CTL, state->msr_rtit_ctl);
	wrmsrl(MSR_ARCH_LBR_CTL, state->msr_lbr_ctl);

}

static void save_guest_state(struct vm_guest_state *state)
{
	state->cr2 = read_cr2();
	state->cr8 = read_cr8();
}

static void load_guest_state(struct vm_guest_state *state)
{
	write_cr2(state->cr2);
	write_cr8(state->cr8);
}

asmlinkage unsigned long
__akvm_vcpu_run(struct vm_host_state *hs, struct vm_guest_state *gs,
		int launched);

static int vm_enter_exit(struct vm_context *vm)
{
	unsigned long r;

	r = __akvm_vcpu_run(&vm->host_state, &vm->guest_state,
			    vm->launched);
	if (!r) {
		vm->exit.val = vmcs_read_32(VMX_EXIT_REASON);
		vm->intr_info.val = vmcs_read_32(VMX_EXIT_INTR_INFO);
		vm->intr_error_code = vmcs_read_32(VMX_EXIT_INTR_ERROR_CODE);
		vm->launched = true;
		return r;
	}

	switch(r) {
	case 1:
		pr_err("failed vmentry: instruction error:0x%lx\n",
		       vmcs_read_32(VMX_INSTRUCTION_ERROR));
		break;
	case 2:
		pr_err("failedInvalid vmentry:\n");
		break;
	default:
		pr_err("failed unknown\n");
		break;
	}

	return r;
}

static int handle_vm_exit(struct vm_context *vm)
{
	pr_info("exit_reason: 0x%x\n", vm->exit.val);
	return 0;
}

extern void __akvm_call_host_intr(unsigned long);

static int do_host_intr(struct vm_context *vm)
{
	unsigned long handler;
	union idt_entry64 *idte;
	struct gdt_idt_table_desc idt_desc;

	if (WARN_ON(!vm->intr_info.valid))
		return -EINVAL;

	if (WARN_ON(vm->intr_info.type != VMX_INTR_TYPE_EXTERNAL))
		return -EINVAL;

	get_idt_table_desc(&idt_desc);
	idte = (void*)idt_desc.base;
	handler = get_idt_entry_point(idte + vm->intr_info.vector);

	__akvm_call_host_intr(handler);
	return 0;
}

static int do_host_nmi(struct vm_context *vm)
{
	if (WARN_ON(!vm->intr_info.valid))
		return -EINVAL;

	if (WARN_ON(vm->intr_info.type != VMX_INTR_TYPE_NMI))
		return -EINVAL;

	__akvm_call_host_intr((unsigned long)asm_exc_nmi_kvm_vmx);
	return 0;
}

static int handle_vm_exit_irqoff(struct vm_context *vm)
{
	switch (vm->exit.reason) {
	case VMX_EXIT_EXCEP_NMI:
		return do_host_nmi(vm);
	case VMX_EXIT_INTR:
		return do_host_intr(vm);
	default:
		return 0;
	}
}

static int akvm_ioctl_run(struct file *f, unsigned long param)
{
	unsigned long flags;

	/*
	  prepare VMCS and sub struct
		alloc vmcs and sub struct
	  PREEMPTION_DISABLE()
	  VMX ON
		setup exec/vmetnry/vmexit control fields
	  load vmcs
	  prepare host state
	  prepare guest state
	  vmlaunch

	  vmcs clear
	  free vmcs
	  VMX OFF
	  PREEMPTION_ENABLE()
	 */
	int r;

	r = alloc_vmcs(&vm_context);
	if (r)
		return r;

	prepare_vmx_region(vm_context.vmx_region,
			   vmx_region_size(&vmx_capability),
			   vmx_vmcs_revision(&vmx_capability));
	preempt_disable();
	vmx_on(vm_context.vmx_region);
	prepare_vmcs(vm_context.vmcs,
		     vmx_region_size(&vmx_capability),
		     vmx_vmcs_revision(&vmx_capability));
	vmcs_load(vm_context.vmcs);

	r = setup_vmcs_control(&vm_context, &vmx_capability);
	if (r)
		goto exit;
	r = setup_vmcs_host_state(&vm_context);
	if (r)
		goto exit;
	setup_ept_root(&vm_context, &vmx_capability);

	r = setup_vmcs_guest_state(&vm_context, &vmx_capability);
	if (r)
		goto exit;

	local_irq_save(flags);

	save_host_state(&vm_context.host_state);
	load_guest_state(&vm_context.guest_state);

	r = vm_enter_exit(&vm_context);

	save_guest_state(&vm_context.guest_state);
	load_host_state(&vm_context.host_state);

	if (!r && !vm_context.exit.failed)
		handle_vm_exit_irqoff(&vm_context);

	local_irq_restore(flags);

	if (!r && !vm_context.exit.failed)
		handle_vm_exit(&vm_context);
 exit:
	vmcs_clear(vm_context.vmcs);
	vmx_off();
	preempt_enable();

	vm_context.launched = false;

	free_vmcs(&vm_context);

	return r;
}

static int akvm_ioctl_get_vmx_info(struct file *f, unsigned long param)
{
	struct akvm_vmx_info vmx_info;

	vmx_info.vmx_basic_msr = vmx_capability.msr_vmx_basic;
	vmx_info.vmx_misc_msr = vmx_capability.msr_vmx_misc;
	vmx_info.vmx_ept_vpid_msr = vmx_capability.msr_ept_vpid;

	if (copy_to_user((void __user*)param, &vmx_info, sizeof(vmx_info)))
		return -EFAULT;

	return 0;
}

static long akvm_dev_ioctl(struct file *f, unsigned int ioctl,
			   unsigned long param)
{
	int r;

	switch(ioctl) {
	case AKVM_RUN:
		r = akvm_ioctl_run(f, param);
		break;
	case AKVM_GET_VMX_INFO:
		r = akvm_ioctl_get_vmx_info(f, param);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static struct file_operations akvm_dev_ops = {
	.unlocked_ioctl = akvm_dev_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice akvm_dev = {
	MISC_DYNAMIC_MINOR,
	"akvm",
	&akvm_dev_ops,
};

static int __init akvm_init(void)
{
	int r;

	r = probe_vmx_basic_info(&vmx_capability);
	if (r) {
		pr_err("akvm: failed to probe VMX basic information\n");
		goto exit;
	}

	r = misc_register(&akvm_dev);
	if (r)
		pr_err("akvm: failed to register device\n");

 exit:
	return r;
}

static void __exit akvm_exit(void)
{
	misc_deregister(&akvm_dev);
}

module_init(akvm_init);
module_exit(akvm_exit);
MODULE_LICENSE("GPL");
