#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/percpu.h>
#include <linux/anon_inodes.h>

#include <uapi/linux/akvm.h>

#include <asm/msr-index.h>
#include <asm/cpu_entry_area.h>
#include <asm/idtentry.h>
#include <asm/desc.h>

#include "common.h"
#include "vcpu.h"
#include "vm.h"
#include "vmx.h"
#include "x86.h"

#ifdef _DEBUG
#define akvm_pr_info pr_info
#else
#define akvm_pr_info(...)
#endif

#define VMX_PINBASE_CTL_MIN		       \
	(VMX_PINBASE_EXTERNAL_INTERRUPT_EXIT | \
	 VMX_PINBASE_NMI_EXIT)

#define VMX_PROCBASE_CTL_MIN VMX_PROCBASE_ACTIVE_2ND_CONTROL

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

static void free_vmcs(struct vcpu_context *vcpu)
{
	kfree(vcpu->vmcs.vmcs);
}

static int alloc_vmcs(struct vcpu_context *vcpu)
{
	size_t size = vmx_region_size(&vmx_capability);

	vcpu->vmcs.vmcs = kmalloc(size, GFP_KERNEL_ACCOUNT);
	if (!vcpu->vmcs.vmcs) {
		pr_err("failed to alloc vmcs\n");
		return -ENOMEM;
	}
	vcpu->vmcs.last_cpu = -1;

	return 0;
}

static void __vmcs_clear_on_cpu(void *info)
{
	struct vm_vmcs *vm_vmcs = info;

	list_del(&vm_vmcs->entry);

	smp_wmb();

	vmcs_clear(vm_vmcs->vmcs);
	vm_vmcs->launched = false;
	vm_vmcs->last_cpu = -1;
}

static void __vcpu_put(struct vcpu_context *vcpu, bool sync_put)
{
	if (!sync_put)
		return;

	smp_rmb();
	if (vcpu->vmcs.last_cpu == -1)
		return;

	smp_call_function_single(vcpu->vmcs.last_cpu,
				 __vmcs_clear_on_cpu, &vcpu->vmcs, 1);
}

static void vcpu_put(struct vcpu_context *vcpu, bool sync_put)
{
	preempt_disable();

	preempt_notifier_unregister(&vcpu->preempt_notifier);

	__vcpu_put(vcpu, sync_put);

	preempt_enable();
}

static int __vcpu_load(struct vcpu_context *vcpu)
{
	unsigned long flag;
	int cpu = smp_processor_id();
	int r = 0;

	smp_rmb();

	if (vcpu->vmcs.last_cpu != -1)
		__vcpu_put(vcpu, true);

	r = vmcs_load(vcpu->vmcs.vmcs);
	if (r)
		goto exit;

	vcpu->vmcs.launched = false;
	vcpu->vmcs.last_cpu = cpu;

	/*
	  make sure launch/last_cpu become visible before
	  insert to list
	*/
	smp_wmb();

	local_irq_save(flag);
	list_add(&vcpu->vmcs.entry, &per_cpu(vmcs_list, cpu).head);
	local_irq_restore(flag);
 exit:
	return r;
}

static int vcpu_load(struct vcpu_context *vcpu)
{
	int cpu;
	int r;

	preempt_disable();
	cpu = smp_processor_id();

	preempt_notifier_init(&vcpu->preempt_notifier,
			      &akvm_preempt_ops);
	preempt_notifier_register(&vcpu->preempt_notifier);

	r = __vcpu_load(vcpu);

	preempt_enable();
	return r;
}

static int setup_vmcs_control(struct vcpu_context *vcpu,
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

	vcpu->pinbase_ctl = vmx_pinbase;
	vcpu->procbase_ctl = vmx_procbase;
	vcpu->procbase_2nd_ctl = vmx_procbase_2nd;
	vcpu->entry_ctl = vmx_entry;
	vcpu->exit_ctl = vmx_exit;

	return 0;
}

static int setup_vmcs_host_state(struct vcpu_context *vcpu)
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
	int cpu;

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

	vmcs_write_natural(VMX_HOST_RIP, (unsigned long)akvm_vmx_vmexit);

	vmcs_write_16(VMX_HOST_CS, get_cs());
	vmcs_write_16(VMX_HOST_SS, get_ss());
	vmcs_write_16(VMX_HOST_DS, get_ds());
	vmcs_write_16(VMX_HOST_ES, get_es());
	vmcs_write_16(VMX_HOST_FS, get_fs());
	vmcs_write_16(VMX_HOST_GS, get_gs());
	vmcs_write_16(VMX_HOST_TR, get_tr());

	vmcs_write_natural(VMX_HOST_FS_BASE, get_fsbase());
	akvm_pr_info("fsbase: 0x%lx\n", get_fsbase());

	vmcs_write_natural(VMX_HOST_GS_BASE, get_gsbase());
	akvm_pr_info("gsbase: 0x%lx\n", get_gsbase());

	cpu = get_cpu();
	vmcs_write_natural(VMX_HOST_TR_BASE,
			   (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
	akvm_pr_info("tr_base: 0x%lx\n", (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
	put_cpu();

	get_gdt_table_desc(&gdt_idt_desc);
	vmcs_write_natural(VMX_HOST_GDT_BASE, gdt_idt_desc.base);
	akvm_pr_info("gdt: base:0x%lx size:%d\n",
		gdt_idt_desc.base, (int)gdt_idt_desc.size);

	get_idt_table_desc(&gdt_idt_desc);
	vmcs_write_natural(VMX_HOST_IDT_BASE, gdt_idt_desc.base);
	akvm_pr_info("idt: base:0x%lx size:%d\n",
		gdt_idt_desc.base, (int)gdt_idt_desc.size);

	rdmsr(MSR_IA32_SYSENTER_CS, msr_val.low, msr_val.high);
	vmcs_write_32(VMX_HOST_IA32_SYSENTER_CS, msr_val.low);
	akvm_pr_info("sysenter_cs: 0x%x\n", msr_val.low);

	rdmsr(MSR_IA32_SYSENTER_ESP, msr_val.low, msr_val.high);
	vmcs_write_natural(VMX_HOST_IA32_SYSENTER_ESP, msr_val.val);
	akvm_pr_info("sysenter_esp: 0x%lx\n", msr_val.val);

	rdmsr(MSR_IA32_SYSENTER_EIP, msr_val.low, msr_val.high);
	vmcs_write_natural(VMX_HOST_IA32_SYSENTER_EIP, msr_val.val);
	akvm_pr_info("sysenter_eip: 0x%lx\n", msr_val.val);

	return 0;
}

static void setup_ept_root(struct vcpu_context *vcpu,
			   struct vmx_capability *cap)
{
	unsigned long ept_val;
	unsigned long ept_root = akvm_mmu_root_page(&vcpu->vm->mmu);

	if (!ept_root) {
		akvm_pr_info("ept_root: skip due to no ept_root page\n");
		return;
	}

	WARN_ON(!vmx_ept_mem_type_wb(cap));

	ept_val = __pa(ept_root) & PAGE_MASK;
	ept_val |= VMX_EPT_MEM_TYPE_WB;
	ept_val |= (vmx_ept_level(cap) - 1) << VMX_EPT_WALK_LENGTH_SHIFT;
	if (vmx_ept_ad_bit(cap))
		ept_val |= VMX_EPT_ENABLE_AD_BITS;

	vcpu->ept_root_cached = ept_val;
	vmcs_write_64(VMX_EPTP_POINTER, ept_val);
	akvm_pr_info("ept_root: 0x%lx\n", ept_val);
}

static void setup_vmcs_guest_state(struct vcpu_context *vcpu,
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
	if ((vcpu->procbase_2nd_ctl & VMX_PROCBASE_2ND_UNRESTRICT_GUEST) &&
	    (vcpu->procbase_2nd_ctl & VMX_PROCBASE_2ND_ENABLE_EPT) &&
	    (vcpu->procbase_ctl & VMX_PROCBASE_ACTIVE_2ND_CONTROL))
		val &= ~(X86_CR0_PG | X86_CR0_PE);
	vmcs_write_natural(VMX_GUEST_CR0, val);
	akvm_pr_info("guest cr0: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_CR3, val);
	akvm_pr_info("guest cr3: 0x%lx\n", val);

	val = cap->cr4_fixed1;
	vmcs_write_natural(VMX_GUEST_CR4, val);
	akvm_pr_info("guest cr4: 0x%lx\n", val);

	val = X86_DR7_RESERVED_1;
	vmcs_write_natural(VMX_GUEST_DR7, val);
	akvm_pr_info("guest dr7: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_RIP, val);
	akvm_pr_info("guest rip: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_RSP, val);
	akvm_pr_info("guest rsp: 0x%lx\n", val);

	val = X86_FLAGS_RESERVED_1;
	vmcs_write_natural(VMX_GUEST_RFLAGS, val);
	akvm_pr_info("guest rflags: 0x%lx\n", val);

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
	akvm_pr_info("guest data seg: base:0x%x limit:0x%x ar:0x%x\n",
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
	akvm_pr_info("guest code seg: base:0x%x limit:0x%x ar:0x%x\n",
		code_seg.base, code_seg.limit, code_seg.ar.val);
	vmcs_write_16(VMX_GUEST_CS, code_seg.selector.val);
	vmcs_write_natural(VMX_GUEST_CS_BASE, code_seg.base);
	vmcs_write_32(VMX_GUEST_CS_LIMIT, code_seg.limit);
	vmcs_write_32(VMX_GUEST_CS_AR, code_seg.ar.val);

	ldtr_seg.base = 0;
	ldtr_seg.limit= 0xffff;
	ldtr_seg.selector.val = 0;
	ldtr_seg.ar.unusable = true;
	akvm_pr_info("guest ldtr seg: base:0x%x limit:0x%x ar:0x%x\n",
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
	akvm_pr_info("guest tr seg: base:0x%x limit:0x%x ar:0x%x\n",
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
	akvm_pr_info("guest gdt: base:0x%lx limit:0x%lx\n", val, val);
	vmcs_write_natural(VMX_GUEST_IDTR_BASE, val);
	vmcs_write_32(VMX_GUEST_IDTR_LIMIT, val);
	akvm_pr_info("guest idt: base:0x%lx limit:0x%lx\n", val, val);

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
	akvm_pr_info("guest activity: 0x%lx\n", val);

	val = 0;
	vmcs_write_32(VMX_GUEST_INTR_BLOCK, val);
	akvm_pr_info("guest intr block: 0x%lx\n", val);

	val = 0;
	vmcs_write_natural(VMX_GUEST_PENDING_DB_EXCEPT, val);
	akvm_pr_info("guest pending #DB: 0x%lx\n", val);

	val = -1ULL;
	vmcs_write_64(VMX_GUEST_VMCS_LINK_POINTER, val);
	akvm_pr_info("guest vmcs link pointer: 0x%lx\n", val);
}

static void save_host_state(struct vm_host_state *state)
{
	int i;
	unsigned long val;

	vmcs_write_natural(VMX_HOST_CR0, read_cr0());
	vmcs_write_natural(VMX_HOST_CR3, __read_cr3());
	vmcs_write_natural(VMX_HOST_CR4, __read_cr4());
	state->cr8 = read_cr8();

	rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, val);
	vmcs_write_64(VMX_HOST_IA32_PERF_GLOBAL_CTL, val);
	akvm_pr_info("perf_global_ctl: 0x%lx\n", val);

	rdmsrl(MSR_IA32_CR_PAT, val);
	vmcs_write_64(VMX_HOST_IA32_PAT, val);
	akvm_pr_info("ia32_pat: 0x%lx\n", val);

	rdmsrl(MSR_EFER, val);
	vmcs_write_64(VMX_HOST_IA32_EFER, val);
	akvm_pr_info("ia32_efer: 0x%lx\n", val);

	rdmsrl(MSR_IA32_PKRS, val);
	vmcs_write_64(VMX_HOST_IA32_PKRS, val);
	akvm_pr_info("ia32_pkrs: 0x%lx\n", val);

	rdmsrl(MSR_IA32_DEBUGCTLMSR, state->msr_debugctl);
	rdmsrl(MSR_IA32_RTIT_CTL, state->msr_rtit_ctl);
	rdmsrl(MSR_ARCH_LBR_CTL, state->msr_lbr_ctl);

	for (i = 0; i < 8; ++i) {
		if (i == 4 || i == 5)
			continue;
		state->dr[i] = read_dr(i);
	}

	/* update "per cpu" context below, part refer virt/kvm/kvm_main.c */
	vmcs_write_natural(VMX_HOST_FS_BASE, get_fsbase());
	akvm_pr_info("fsbase: 0x%lx\n", get_fsbase());

	vmcs_write_natural(VMX_HOST_GS_BASE, get_gsbase());
	akvm_pr_info("gsbase: 0x%lx\n", get_gsbase());
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

static void __vcpu_ipi_kicker(void *unused)
{
	return;
}

void akvm_vcpu_kick(struct vcpu_context *vcpu)
{
	int old;

	/*
	  only "sync" vcpu_put(vcpu, true) set this to -1, it's rare and
	  happen only when deinit the vcpu, so check w/o lock
	  should be ok here
	 */
	if (vcpu->vmcs.last_cpu == -1)
		return;

	/*
	  set to leave_guest successfully so the next vm_enter will
	  be skipped, thus don't need the ipi kicker
	*/
	old = set_run_state(vcpu, VCPU_IN_HOST, VCPU_LEAVE_GUEST);
	if (old == VCPU_IN_HOST)
		return;

	/* already in "host" thus the ipi kicker can be skipped */
	if (old == VCPU_LEAVE_GUEST)
		return;

	smp_call_function_single(vcpu->vmcs.last_cpu,
				 __vcpu_ipi_kicker, NULL, 1);
}

void akvm_vcpu_set_request(struct vcpu_context *vcpu, unsigned long request,
			   bool urgent)
{
	set_bit(request, &vcpu->requests);

	/* pair with test_and_clear_bit() in  akvm_vcpu_check_request() */
	smp_wmb();

	if (urgent)
		akvm_vcpu_kick(vcpu);
}

asmlinkage unsigned long
__akvm_vcpu_run(struct vm_host_state *hs, struct vm_guest_state *gs,
		int launched);

static int vm_enter_exit(struct vcpu_context *vcpu)
{
	unsigned long r;

	set_run_state_in_guest(vcpu);

	r = __akvm_vcpu_run(&vcpu->host_state, &vcpu->guest_state,
			    vcpu->vmcs.launched);
	if (!r) {
		vcpu->exit.val = vmcs_read_32(VMX_EXIT_REASON);
		vcpu->intr_info.val = vmcs_read_32(VMX_EXIT_INTR_INFO);
		vcpu->intr_error_code = vmcs_read_32(VMX_EXIT_INTR_ERROR_CODE);
		vcpu->vmcs.launched = true;
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

static int do_ept_violation(struct vcpu_context *vcpu)
{
	gpa fault_addr = vmcs_read_64(VMX_EXIT_GPA);

	return akvm_handle_mmu_page_fault(vcpu, &vcpu->vm->mmu, fault_addr);
};

static int handle_vm_exit(struct vcpu_context *vcpu)
{
	switch (vcpu->exit.reason) {
	/*
	  current ignore due to irqoff handler already
	  called host handler
	*/
	case VMX_EXIT_EXCEP_NMI:
		fallthrough;
	case VMX_EXIT_INTR:
		return 0;
	case VMX_EXIT_EPT_VIOLATION:
		return do_ept_violation(vcpu);
	default:
		pr_err("unimplemented vmexit: %d\n", vcpu->exit.reason);
		return -ENOTSUPP;
	}
}

extern void __akvm_call_host_intr(unsigned long);

static int do_host_intr(struct vcpu_context *vcpu)
{
	unsigned long handler;
	union idt_entry64 *idte;
	struct gdt_idt_table_desc idt_desc;

	if (WARN_ON(!vcpu->intr_info.valid))
		return -EINVAL;

	if (WARN_ON(vcpu->intr_info.type != VMX_INTR_TYPE_EXTERNAL))
		return -EINVAL;

	get_idt_table_desc(&idt_desc);
	idte = (void*)idt_desc.base;
	handler = get_idt_entry_point(idte + vcpu->intr_info.vector);

	__akvm_call_host_intr(handler);
	return 0;
}

static int do_host_nmi(struct vcpu_context *vcpu)
{
	if (WARN_ON(!vcpu->intr_info.valid))
		return -EINVAL;

	if (WARN_ON(vcpu->intr_info.type != VMX_INTR_TYPE_NMI))
		return -EINVAL;

	__akvm_call_host_intr((unsigned long)asm_exc_nmi_kvm_vmx);
	return 0;
}

static int handle_vm_exit_irqoff(struct vcpu_context *vcpu)
{
	switch (vcpu->exit.reason) {
	case VMX_EXIT_EXCEP_NMI:
		return do_host_nmi(vcpu);
	case VMX_EXIT_INTR:
		return do_host_intr(vcpu);
	default:
		return 0;
	}
}

static int akvm_handle_vcpu_request_flush_tlb(struct vcpu_context *vcpu)
{
	if (vmx_ept_invept_single_context(&vmx_capability))
		return invept(vcpu->ept_root_cached);
	else
		return invept(0);
}

static int akvm_vcpu_handle_requests(struct vcpu_context *vcpu)
{
	int r = 0;

	return r;
}

static int akvm_vcpu_handle_requests_irqoff(struct vcpu_context *vcpu)
{
	int r = 0;

	if (test_and_clear_bit(AKVM_VCPU_REQUEST_FLUSH_TLB, &vcpu->requests))
		r = akvm_handle_vcpu_request_flush_tlb(vcpu);

	return r;
}

static int akvm_ioctl_run(struct vcpu_context *vcpu, unsigned long param)
{
	unsigned long flags;
	int r;

	vcpu_load(vcpu);

	r = setup_vmcs_host_state(vcpu);
	if (r)
		goto exit;
	setup_ept_root(vcpu, &vmx_capability);

	while(!r) {
		if (signal_pending(current)) {
			r = 1;
			break;
		}

		if (need_resched())
			cond_resched();

		r = akvm_vcpu_handle_requests(vcpu);
		if (r)
			break;

		preempt_disable();
		local_irq_save(flags);

		/*
		  kick vcpu set state to leave_guest to request
		  out of this run loop for i.e. event handling.
		*/
		if (!set_run_state_enter_guest(vcpu)) {
			r = 1;
			goto irq_enable;
		}

		r = akvm_vcpu_handle_requests_irqoff(vcpu);
		if (r)
			goto irq_enable;

		save_host_state(&vcpu->host_state);
		load_guest_state(&vcpu->guest_state);

		r = vm_enter_exit(vcpu);

		save_guest_state(&vcpu->guest_state);
		load_host_state(&vcpu->host_state);

		set_run_state_leave_guest(vcpu);

		if (!r && !vcpu->exit.failed)
			handle_vm_exit_irqoff(vcpu);
irq_enable:
		local_irq_restore(flags);
		preempt_enable();

		set_run_state_in_host(vcpu);

		if (!r && !vcpu->exit.failed)
			r = handle_vm_exit(vcpu);
	}
 exit:
	vcpu_put(vcpu, false);

	return r;
}

void akvm_vcpu_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct vcpu_context *vcpu =
		container_of(pn, struct vcpu_context, preempt_notifier);

	__vcpu_load(vcpu);

	/* update "per cpu" context below, part refer virt/kvm/kvm_main.c */
	vmcs_write_natural(VMX_HOST_TR_BASE,
			   (unsigned long)&get_cpu_entry_area(cpu)->tss.x86_tss);
	vmcs_write_natural(VMX_HOST_GDT_BASE, (unsigned long)get_cpu_gdt_ro(cpu));

	if (IS_ENABLED(CONFIG_IA32_EMULATION) || IS_ENABLED(CONFIG_X86_32))
		vmcs_write_natural(VMX_HOST_IA32_SYSENTER_ESP,
				   (unsigned long)(cpu_entry_stack(cpu) + 1));

	akvm_vcpu_set_request(vcpu, AKVM_VCPU_REQUEST_FLUSH_TLB, false);
}

void akvm_vcpu_sched_out(struct preempt_notifier *pn,
			  struct task_struct *next)
{
	struct vcpu_context *vcpu =
		container_of(pn, struct vcpu_context, preempt_notifier);

	__vcpu_put(vcpu, false);
}

static void akvm_deinit_vcpu(struct vcpu_context *vcpu)
{
	/* pair to flush vmcs  */
	vcpu_load(vcpu);
	vcpu_put(vcpu, true);
	free_vmcs(vcpu);
}

static int akvm_vcpu_open(struct inode *inode, struct file *file)
{
	pr_info("%s\n", __func__);
	return 0;
}

static int akvm_vcpu_release(struct inode *inode, struct file *file)
{
	struct vcpu_context *vcpu = file->private_data;
	vcpu_destroy_notifier vcpu_destroy_cb = vcpu->vm->vcpu_destroy_cb;
	struct file *vm_file = vcpu->vm_file;

	pr_info("%s\n", __func__);

	akvm_deinit_vcpu(vcpu);

	if (vcpu_destroy_cb)
		vcpu_destroy_cb(vcpu->vm, vcpu->index);

	kfree(vcpu);

	if (vm_file)
		fput(vm_file);
	return 0;
}

static long akvm_vcpu_ioctl(struct file *f, unsigned int ioctl,
			  unsigned long param)
{
	int r = 0;
	struct vcpu_context *vcpu = f->private_data;

	if (!vcpu)
		return -EINVAL;

	mutex_lock(&vcpu->ioctl_lock);

	switch(ioctl) {
	case AKVM_RUN:
		r = akvm_ioctl_run(vcpu, param);
		break;
	default:
		r = -EINVAL;
	}

	mutex_unlock(&vcpu->ioctl_lock);

	return r;
}

static struct file_operations akvm_vcpu_ops = {
	.open = akvm_vcpu_open,
	.unlocked_ioctl = akvm_vcpu_ioctl,
	.llseek = noop_llseek,
	.release = akvm_vcpu_release,
	.owner = THIS_MODULE,
};

static int akvm_init_vcpu(struct vcpu_context *vcpu)
{
	int r;

	r = alloc_vmcs(vcpu);
	if (r)
		return r;

	prepare_vmcs(vcpu->vmcs.vmcs,
		     vmx_region_size(&vmx_capability),
		     vmx_vmcs_revision(&vmx_capability));

	vcpu_load(vcpu);

	r = setup_vmcs_control(vcpu, &vmx_capability);
	if (r)
		goto failed_put;
	setup_vmcs_guest_state(vcpu, &vmx_capability);

	vcpu_put(vcpu, false);

	mutex_init(&vcpu->ioctl_lock);
	return r;

failed_put:
	vcpu_put(vcpu, true);
	free_vmcs(vcpu);
	return r;
}

int akvm_create_vcpu(struct file *vm_file,
		     struct vm_context *vm, int vcpu_index)
{
	int r;
	int fd;
	struct file *file;
	struct vcpu_context *vcpu;
	vcpu_create_notifier vm_create_vcpu_cb = vm->vcpu_create_cb;

	vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL_ACCOUNT);
	if (!vcpu)
		return -ENOMEM;

	r = akvm_init_vcpu(vcpu);
	if (r)
		goto failed_free;

	r = get_unused_fd_flags(O_CLOEXEC);
	if (r < 0)
		goto failed_deinit_vcpu;

	file = anon_inode_getfile("akvm-vcpu", &akvm_vcpu_ops, vcpu, O_RDWR);
	if (IS_ERR(file)) {
		r = PTR_ERR(file);
		goto failed_fdput;
	}

	fd = r;
	if (vm_create_vcpu_cb) {
		r = vm_create_vcpu_cb(vm, vcpu_index, vcpu);
		if (r)
			goto failed_fput;
	}

	if (vm_file)
		vcpu->vm_file = get_file(vm_file);
	vcpu->index = vcpu_index;
	vcpu->vm = vm;

	fd_install(fd, file);
	pr_info("install fd:%d\n", fd);
	return fd;

failed_fput:
	fput(file);
failed_fdput:
	put_unused_fd(fd);
failed_deinit_vcpu:
	akvm_deinit_vcpu(vcpu);
failed_free:
	kfree(vcpu);
	return r;

}
