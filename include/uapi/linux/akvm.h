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

#define AKVM_RUN		_IO(AKVMIO,   0x00)

struct akvm_vmx_info {
	__u64 vmx_basic_msr;
	__u64 vmx_misc_msr;
	__u64 vmx_ept_vpid_msr;
};
#define AKVM_GET_VMX_INFO	_IOR(AKVMIO,  0x01, struct akvm_vmx_info)
#define AKVM_CREATE_VM   _IO(AKVMIO,   0x02)
#define AKVM_CREATE_VCPU _IO(AKVMIO,   0x03)

struct akvm_memory_slot {
	__u64 hva;
	__u64 gpa;
	__u64 size;
	__u64 flags;
};
#define AKVM_MEMORY_SLOT_ADD _IOR(AKVMIO, 0x4, struct akvm_memory_slot)
#define AKVM_MEMORY_SLOT_REMOVE _IOR(AKVMIO, 0x5, struct akvm_memory_slot)

/* hva/gpa/size need aligning on this value */
#define AKVM_MEMORY_SLOT_ALIGN 4096

struct akvm_vcpu_runtime {
	__u64 exit_reason;
};
#define AKVM_VCPU_RUNTIME_PG_OFF 0ULL

#endif /* __LINUX_AKVM_H */
