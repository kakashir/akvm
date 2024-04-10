#ifndef __CPUID_H
#define __CPUID_H

#include <linux/types.h>
#include <asm/cpufeature.h>
#include "common.h"

/*
	cpuid 1  Common feautre expose
		ecx [k]
		edx [k]
	cpuid 6 thermal and power
		eax [k]
	cpuid 7 structured extend feature leaf
		ebx [k]
		ecx [k]
		edx [k]
		sub leaf 1
			eax [akvm]
			ebx [akvm]
			ecx [akvm]
			edx [akvm]
		sub leaf 2
			eax [akvm]
			ebx [akvm]
			ecx [akvm]
			edx [akvm]
	cpuid 0xa PMU
		eax [akvm]
		ebx [akvm]
		ecx [akvm]
		edx [akvm]
	cpuid 0xd cpu extend state (XSAVE)
		eax [akvm]
		ebx [akvm]
		ecx [akvm]
		edx [akvm]
		sub leaf 1
			eax [k]
			ebx [akvm]
			ecx [akvm]
			edx [akvm]
		sub leaf N (N > 1)
			eax [akvm]
			ebx [akvm]
			ecx [akvm]
			edx [akvm]
	cpuid 0x12 SGX (not support)
	cpuid 0x14 intel pt (not support)
	cpuid 0x15 TSC and core crystal clock information
		eax [akvm]
		ebx [akvm]
		ecx [akvm]
		edx [akvm]
	cpuid 0x16 cpu frequency information
		eax [akvm]
		ebx [akvm]
		ecx [akvm]
		edx [akvm]
	cpuid 0x17 SoC vendor information (not supported)
	cpuid 0x18 TLB information (user space to set)
	cpuid 0x19 keylocker (not support)
	cpuid 0x1a Native model id  (user space to set)
	cpuid 0x1b pconfig (not support)
	cpuid 0x1c lbr (not support)
	cpuid 0x1d tile information (from hw)
		eax [akvm]
		ebx [akvm]
		ecx [akvm]
		edx [akvm]
	cpuid 0x1e tmul information (from hw)
		eax [akvm]
		ebx [akvm]
		ecx [akvm]
		edx [akvm]
	cpuid 0x1f extend cpu topology  (from user space)
	cpuid 0x20 processor history (not supported)
	cpuid 0x80000001 extend feature cpuid
		eax
		ebx
		ecx
		edx
	cpuid 0x80000002 ~ 0x80000005 cpud brand string (from user space)
	cpuid 0x80000006 (from user space)
	cpuid 0x80000007
		edx [akvm]
	cpuid 0x80000008
		eax [akvm]
		ebx [k]
		ecx [akvm]
		edx [akvm]

 */

enum akvm_cpuid_leafs {
	AKVM_CPUID_7_1_EBX = NCAPINTS,
	AKVM_CPUID_7_1_ECX,
	AKVM_CPUID_7_1_EDX,

	AKVM_CPUID_7_2_EAX,
	AKVM_CPUID_7_2_EBX,
	AKVM_CPUID_7_2_ECX,
	AKVM_CPUID_7_2_EDX,

	NAKVMCAPINTS,
};

/* features not store kerne's cpu leaf array, but may suppported by akvm */
#define X86_FEATURE_PPIN_CTRL (AKVM_CPUID_7_1_EBX * 32 + 0)

#define X86_FEATURE_CET_SSS (AKVM_CPUID_7_1_EDX * 32 + 18)

#define X86_FEATURE_MCDT_NO (AKVM_CPUID_7_2_EDX * 32 + 0)

int akvm_cpuid_init(void);

#endif
