/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_AKVM_H
#define __LINUX_AKVM_H

/*
 * Userspace interface for /dev/akvm
 */

#include <linux/const.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/ioctl.h>
#include <asm/kvm.h>

#define AKVM_MAX_VCPU_NUM 128

#define AKVMIO 0xCC

/* per vcpu level: */
#define AKVM_RUN		_IO(AKVMIO, 0x00)

/* akvm dev level: */
struct akvm_vmx_info {
	__u64 vmx_basic_msr;
	__u64 vmx_misc_msr;
	__u64 vmx_ept_vpid_msr;
};
#define AKVM_GET_VMX_INFO	_IOR(AKVMIO, 0x01, struct akvm_vmx_info)

/* akvm dev level: */
#define AKVM_CREATE_VM   _IO(AKVMIO, 0x02)

/* per vm level: */
#define AKVM_CREATE_VCPU _IO(AKVMIO, 0x03)

/* per vm level: */
struct akvm_memory_slot {
	__u64 hva;
	__u64 gpa;
	__u64 size;
	__u64 flags;
};
#define AKVM_MEMORY_SLOT_ADD _IOR(AKVMIO, 0x4, struct akvm_memory_slot)
#define AKVM_MEMORY_SLOT_REMOVE _IOR(AKVMIO, 0x5, struct akvm_memory_slot)
/* hva/gpa/size need align on this value */
#define AKVM_MEMORY_SLOT_ALIGN 4096

/* per vcpu */
#define AKVM_VCPU_SET_RIP	_IOR(AKVMIO, 0x6, long)

/* akvm dev level  */
struct akvm_cpuid_entry {
	__u32 leaf;
	__u32 sub_leaf;
	union {
		__u32 data[4];
		struct {
			__u32 eax;
			__u32 ebx;
			__u32 ecx;
			__u32 edx;
		};
	};
};

struct akvm_cpuid {
	/*
	  in: the entries number of entry[].
	  out: the actual count writen by kernel
	*/
	__u64 count;
	struct akvm_cpuid_entry *entry;
};
#define AKVM_GET_CPUID		_IOWR(AKVMIO, 0x7, struct akvm_cpuid)

/* Set per cpu guest cpuid */
#define AKVM_VCPU_SET_CPUID	_IOW(AKVMIO, 0x8, struct akvm_cpuid)

#define VM_SERVICE_SUCCESS 0LL

struct akvm_vcpu_runtime {
#define AKVM_EXIT_VM_SERVICE 1 /* see "vm_service" */
#define AKVM_VM_SERVICE_IN_OUT_COUNT 6
	__u64 exit_reason;
	union {
		struct {
			__u64 type;
			__u64 ret;
			__u64 in_out_count;
			__u64 in_out[AKVM_VM_SERVICE_IN_OUT_COUNT];
		} vm_service;
	};
};
#define AKVM_VCPU_RUNTIME_PG_OFF 0ULL

#endif /* __LINUX_AKVM_H */
