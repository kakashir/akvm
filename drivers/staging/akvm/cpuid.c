#include "cpuid.h"
#include "x86.h"

static u32 akvm_cpu_cap[NAKVMCAPINTS];

enum cpuid_reg_type {
	REG_EAX,
	REG_EBX,
	REG_ECX,
	REG_EDX,
};

struct akvm_reverse_cpuid_entry {
	bool valid;
	int leaf;
	int sub_leaf;
	enum cpuid_reg_type reg;
};

static struct akvm_reverse_cpuid_entry akvm_reverse_cpuid[NAKVMCAPINTS] = {
#define R_CPUID(l, s, r) { .valid = true, .leaf = l, .sub_leaf = s, .reg = r }
	[CPUID_1_EDX]		= R_CPUID(1, 0, REG_EDX),
	[CPUID_8000_0001_EDX]	= R_CPUID(0x80000001, 0, REG_EDX),
	/* CPUID_8086_0001_EDX */
	/* CPUID_LNX_1 */
	[CPUID_1_ECX]		= R_CPUID(1, 0, REG_ECX),
	/* CPUID_C000_0001_EDX */
	[CPUID_8000_0001_ECX]	= R_CPUID(0x80000001, 0, REG_ECX),
	/* CPUID_LNX_2 */
	/* CPUID_LNX_3 */
	[CPUID_7_0_EBX]		= R_CPUID(7, 0, REG_EBX),
	[CPUID_D_1_EAX]		= R_CPUID(0xd, 1, REG_EAX),
	/* CPUID_LNX_4 */
	[CPUID_7_1_EAX]		= R_CPUID(7, 1, REG_EAX),
	[CPUID_8000_0008_EBX]	= R_CPUID(0x80000008, 0, REG_EBX),
	[CPUID_6_EAX]		= R_CPUID(6, 0, REG_EAX),
	[CPUID_8000_000A_EDX]	= R_CPUID(0x8000000a, 0, REG_EDX),
	[CPUID_7_ECX]		= R_CPUID(7, 0, REG_ECX),
	[CPUID_8000_0007_EBX]	= R_CPUID(0x80000007, 0, REG_EBX),
	[CPUID_7_EDX]		= R_CPUID(7, 0, REG_EDX),
	[CPUID_8000_001F_EAX]	= R_CPUID(0x8000001f, 0, REG_EAX),
	[CPUID_8000_0021_EAX]	= R_CPUID(0x80000021, 0, REG_EAX),
	/* CPUID_LNX_5*/
	[AKVM_CPUID_7_1_EBX]	= R_CPUID(0x7, 1, REG_EBX),
	[AKVM_CPUID_7_1_ECX]	= R_CPUID(0x7, 1, REG_ECX),
	[AKVM_CPUID_7_1_EDX]	= R_CPUID(0x7, 1, REG_EDX),
	[AKVM_CPUID_7_2_EAX]	= R_CPUID(0x7, 2, REG_EAX),
	[AKVM_CPUID_7_2_EBX]	= R_CPUID(0x7, 2, REG_EBX),
	[AKVM_CPUID_7_2_ECX]	= R_CPUID(0x7, 2, REG_ECX),
	[AKVM_CPUID_7_2_EDX]	= R_CPUID(0x7, 2, REG_EDX),
#undef R_CPUID
};

enum akvm_cpu_cap_op {
	AKVM_CPU_CAP_SKIP,
	AKVM_CPU_CAP_CLEAR,
	AKVM_CPU_CAP_SET,
	AKVM_CPU_CAP_AND,
};

static const char *reg_type_to_str(enum cpuid_reg_type type)
{
	switch(type) {
	case REG_EAX: return "EAX";
	case REG_EBX: return "EBX";
	case REG_ECX: return "ECX";
	case REG_EDX: return "EDX";
	default:
		return "Unknown reg type";
	}
}

static const char *cpuid_leaf_to_str(int cpuid_leaf)
{
#define __LEAF_TO_STR(x) case x: return #x
	switch (cpuid_leaf) {
	__LEAF_TO_STR(CPUID_1_EDX);
	__LEAF_TO_STR(CPUID_8000_0001_EDX);
	__LEAF_TO_STR(CPUID_8086_0001_EDX);
	__LEAF_TO_STR(CPUID_LNX_1);
	__LEAF_TO_STR(CPUID_1_ECX);
	__LEAF_TO_STR(CPUID_C000_0001_EDX);
	__LEAF_TO_STR(CPUID_8000_0001_ECX);
	__LEAF_TO_STR(CPUID_LNX_2);
	__LEAF_TO_STR(CPUID_LNX_3);
	__LEAF_TO_STR(CPUID_7_0_EBX);
	__LEAF_TO_STR(CPUID_D_1_EAX);
	__LEAF_TO_STR(CPUID_LNX_4);
	__LEAF_TO_STR(CPUID_7_1_EAX);
	__LEAF_TO_STR(CPUID_8000_0008_EBX);
	__LEAF_TO_STR(CPUID_6_EAX);
	__LEAF_TO_STR(CPUID_8000_000A_EDX);
	__LEAF_TO_STR(CPUID_7_ECX);
	__LEAF_TO_STR(CPUID_8000_0007_EBX);
	__LEAF_TO_STR(CPUID_7_EDX);
	__LEAF_TO_STR(CPUID_8000_001F_EAX);
	__LEAF_TO_STR(CPUID_8000_0021_EAX);
	__LEAF_TO_STR(CPUID_LNX_5);
	__LEAF_TO_STR(AKVM_CPUID_7_1_EBX);
	__LEAF_TO_STR(AKVM_CPUID_7_1_ECX);
	__LEAF_TO_STR(AKVM_CPUID_7_1_EDX);
	__LEAF_TO_STR(AKVM_CPUID_7_2_EAX);
	__LEAF_TO_STR(AKVM_CPUID_7_2_EBX);
	__LEAF_TO_STR(AKVM_CPUID_7_2_ECX);
	__LEAF_TO_STR(AKVM_CPUID_7_2_EDX);
	default:
		return "unknown cpuid leaf";
	}
#undef __LEAF_TO_STR
}

static bool akvm_incorrect_cpuid_leaf(int cpuid_leaf)
{
	if (cpuid_leaf < 0 || cpuid_leaf >= NAKVMCAPINTS ||
	    !akvm_reverse_cpuid[cpuid_leaf].valid)
		return true;
	return false;
}

static void __akvm_cpu_cap_init(int cpuid_leaf, int cap, bool akvm_cap_mask)
{
	int val[4];
	struct akvm_reverse_cpuid_entry *entry;

	if (akvm_incorrect_cpuid_leaf(cpuid_leaf)) {
		pr_err("incorrect cpuid_leaf: %d\n", cpuid_leaf);
		return;
	}

	entry = &akvm_reverse_cpuid[cpuid_leaf];
	if (!entry->valid)
		return;

	/*
	  akvm_cap_mask = false means just set the
	  akvm_cpu_cap to cap, for cpu features not supported
	  by kernel's cpu feature table, but only supported by
	  akvm itself.
	*/
	if (akvm_cap_mask)
		akvm_cpu_cap[cpuid_leaf] &= cap;
	else
		akvm_cpu_cap[cpuid_leaf] = cap;

	/* filter out the caps not supported by cpu hardware */
	raw_cpuid(entry->leaf, entry->sub_leaf,
		  val, &val[1], &val[2], &val[3]);
	akvm_cpu_cap[cpuid_leaf] &= val[entry->reg];
}

static void akvm_cpu_cap_init(int cpuid_leaf, int cap)
{
	__akvm_cpu_cap_init(cpuid_leaf, cap, true);
}

static void akvm_cpu_cap_define(int cpuid_leaf, int cap)
{
	__akvm_cpu_cap_init(cpuid_leaf, cap, false);
}

static void debug_dump_cpu_cap(void)
{
	for (int i = 0; i < NAKVMCAPINTS; ++i) {
		struct akvm_reverse_cpuid_entry *entry;

		pr_info("XXXXXXXXX: %d\n", i);
		entry = &akvm_reverse_cpuid[i];
		pr_info("cpuid %s: leaf:0x%x sub_leaf:0x%x, reg:%s val:0x%x\n",
			cpuid_leaf_to_str(i),
			entry->leaf, entry->sub_leaf,
			reg_type_to_str(entry->reg),
			akvm_cpu_cap[i]);
	}
}

#define C(x) (1 << ((X86_FEATURE_##x) & 0x1f))
static void akvm_cpu_cap_adjust(void)
{
	akvm_cpu_cap_init(CPUID_1_EDX,
			  /* C(FPU) C(VME) */  C(DE) | C(PSE) |
			  C(TSC) | C(MSR) | C(PAE) |  /* C(MCE) */
			  C(CX8) | C(APIC) | C(SEP) | /* C(MTRR) */
			  C(PGE) | /* C(MCA) */ C(CMOV) | C(PAT) |
			  C(PSE36) | /* C(PN) */ C(CLFLUSH) | /* C(DS) */
			  /* C(ACPI) C(MMX) C(FXSR) C(XMM) */
			  /* C(XMM2) */ C(SELFSNOOP) /* C(HT) C(ACC) */
			  /* C(IA64) C(PBE) */);

	/* No adjustment for AMD CPUID_8000_0001_EDX */
	/* No adjustment for Transmeta CPUID_8086_0001_EDX */
	/* No adjustment for CPUID_LNX_1 */

	akvm_cpu_cap_init(CPUID_1_ECX,
			  /* C(XMM3) C(PCLMULQDQ) C(DTES64) C(MWAIT) */
			  /* C(DSCPL) C(VMX) C(SMX) C(EST) */
			  /* C(TM2) C(SSSE3) C(CID) C(SDBG) */
			  /* C(FMA) */ 	C(CX16) | /* C(XTPR) C(PDCM) */
			  C(PCID) | C(DCA) | /* C(XMM4_1) C(XMM4_2) */
			  C(X2APIC) | C(MOVBE) | C(POPCNT) | C(TSC_DEADLINE_TIMER) |
			  /* C(AES) C(XSAVE) C(OSXSAVE) C(AVX) */
			  /* C(F16C) */	C(RDRAND) /* C(HYPERVISOR) */);

	/* No adjustment to VIA/Cyrix/Centaur CPUID_C000_0001_EDX */
	/* No adjustment to AMD CPUID_8000_0001_ECX */
	/* No adjustment to CPUID_LNX_2 */
	/* No adjustment to CPUID_LNX_3 */

	akvm_cpu_cap_init(CPUID_7_0_EBX,
			  C(FSGSBASE) | /* C(TSC_ADJUST) C(SGX) */ C(BMI1) |
			  /* C(HLE) C(AVX2) C(FDP_EXCPTN_ONLY) */ C(SMEP) |
			  C(BMI2) | C(ERMS) | C(INVPCID) | /* C(RTM) */
			  /* C(CQM) C(ZERO_FCS_FDS) C(MPX) C(RDT_A) */
			  /* C(AVX512F) C(AVX512DQ) */ C(RDSEED) | C(ADX) |
			  C(SMAP) | /* C(AVX512IFMA) */ C(CLFLUSHOPT) | C(CLWB)
			  /* C(INTEL_PT) | C(AVX512PF) | C(AVX512ER) | C(AVX512CD) */
			  /* C(SHA_NI) C(AVX512BW) */);

	akvm_cpu_cap_init(CPUID_D_1_EAX,
			  0 /* C(XSAVEOPT) C(XSAVEC) C(XGETBV1) */
			  /* C(XSAVES) C(XFD) */);

	/* No adjustment to CPUID_LNX_4 */

	akvm_cpu_cap_init(CPUID_7_1_EAX,
			  /* C(AVX_VNNI)  C(AVX512_BF16) */ C(CMPCCXADD) | /* C(ARCH_PERFMON_EXT) */
			  C(FZRM) | C(FSRS) | C(FSRC)
			  /* C(AMX_FP16) C(AVX_IFMA) C(LAM) C(ARCH_PERFMON_EXT) */
			  /* C(LKGS) | C(LAM) */);

	/* No adjustment for AMD CPUID_8000_0008_EBX */

	/* only ARAT is allowed for thermal and power leaf 0x6 */
	akvm_cpu_cap_init(CPUID_6_EAX,
			  /* C(DTHERM) C(IDA) */ C(ARAT) /* C(PLN) */
			  /* C(PTS) C(HWP) C(HWP_NOTIFY) C(HWP_ACT_WINDOW) */
			  /* C(HWP_EPP) C(HWP_PKG_REQ) C(HFI) */);

	/* No adjustment for AMD CPUID_8000_000A_EDX */

	akvm_cpu_cap_init(CPUID_7_ECX,
			  /* C(AVX512VBMI) */ C(UMIP) | /* C(PKU) C(OSPKE) */
			  /* C(WAITPKG) C(AVX512_VBMI2) C(SHSTK) C(GFNI) */
			  /* C(VAES) C(VPCLMULQDQ) C(AVX512_VNNI) C(AVX512_BITALG) */
			  /* C(TME) C(AVX512_VPOPCNTDQ) C(LA57) C(RDPID) */
			  /* C(BUS_LOCK_DETECT) */ C(CLDEMOTE) | C(MOVDIRI) | C(MOVDIR64B)
			  /* C(ENQCMD) C(SGX_LC) */);

	/* No adjustment for AMD CPUID_8000_0007_EBX */

	akvm_cpu_cap_init(CPUID_7_EDX,
			  /* C(AVX512_4VNNIW) C(AVX512_4FMAPS) */ C(FSRM) |
			  /* C(AVX512_VP2INTERSECT) C(SRBDS_CTRL) C(MD_CLEAR) */
			  /* C(RTM_ALWAYS_ABORT) C(TSX_FORCE_ABORT) */
			  C(SERIALIZE) /* C(HYBRID_CPU) C(TSXLDTRK) */
			  /* C(PCONFIG) C(ARCH_LBR) C(IBT) C(AMX_BF16) */
			  /* C(AVX512_FP16) C(AMX_TILE) C(AMX_INT8) */
			  /* C(SPEC_CTRL) C(INTEL_STIBP) C(FLUSH_L1D) */
			  /* C(ARCH_CAPABILITIES) C(CORE_CAPABILITIES) */
			  /* C(SPEC_CTRL_SSBD) */);

	/* No adjustment for AMD CPUID_8000_001F_EAX */
	/* No adjustment for AMD CPUID_8000_0021_EAX */
	/* No adjustment for AMD CPUID_LNX_5 */

	akvm_cpu_cap_define(AKVM_CPUID_7_1_EBX, C(PPIN_CTRL));

	akvm_cpu_cap_define(AKVM_CPUID_7_1_ECX, 0);

	akvm_cpu_cap_define(AKVM_CPUID_7_1_EDX, C(CET_SSS));

	akvm_cpu_cap_define(AKVM_CPUID_7_2_EAX, 0);

	akvm_cpu_cap_define(AKVM_CPUID_7_2_EBX, 0);

	akvm_cpu_cap_define(AKVM_CPUID_7_2_ECX, 0);

	akvm_cpu_cap_define(AKVM_CPUID_7_2_EDX, C(MCDT_NO));
}
#undef C

int akvm_cpuid_init(void)
{
	BUILD_BUG_ON(sizeof(akvm_cpu_cap[0]) !=
		     sizeof(boot_cpu_data.x86_capability[0]));

	memcpy(&akvm_cpu_cap, &boot_cpu_data.x86_capability,
	       NCAPINTS * sizeof(akvm_cpu_cap[0]));
	memset(&akvm_cpu_cap[NCAPINTS], 0,
	       (NAKVMCAPINTS - NCAPINTS) * sizeof(akvm_cpu_cap[0]));

	akvm_cpu_cap_adjust();

	debug_dump_cpu_cap();
	return 0;
}
