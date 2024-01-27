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

#define AKVMIO 0xCC

#define AKVM_RUN		_IO(AKVMIO,   0x00)

struct akvm_vmx_info {
	__u64 reserved;
};
#define AKVM_GET_VMX_INFO	_IOR(AKVMIO,  0x01, struct akvm_vmx_info)

#endif /* __LINUX_AKVM_H */
