/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/segment.h>
#include <asm/unwind_hints.h>

#define WORD_SIZE 8
#define GPRS_RAX_OFFSET (0 * WORD_SIZE)
#define GPRS_RBX_OFFSET (1 * WORD_SIZE)
#define GPRS_RCX_OFFSET	(2 * WORD_SIZE)
#define GPRS_RDX_OFFSET (3 * WORD_SIZE)
#define GPRS_RDI_OFFSET (4 * WORD_SIZE)
#define GPRS_RSI_OFFSET (5 * WORD_SIZE)
#define GPRS_RBP_OFFSET (6 * WORD_SIZE)
#define GPRS_RSP_OFFSET (7 * WORD_SIZE)
#define GPRS_R8_OFFSET (8 * WORD_SIZE)
#define GPRS_R9_OFFSET (9 * WORD_SIZE)
#define GPRS_R10_OFFSET (10 * WORD_SIZE)
#define GPRS_R11_OFFSET (11 * WORD_SIZE)
#define GPRS_R12_OFFSET (12 * WORD_SIZE)
#define GPRS_R13_OFFSET (13 * WORD_SIZE)
#define GPRS_R14_OFFSET (14 * WORD_SIZE)
#define GPRS_R15_OFFSET (15 * WORD_SIZE)
#define HOST_RFLAGS_OFFSET (0 * WORD_SIZE)

#define ASM_VMX_HOST_RSP $0x6c14

SYM_FUNC_START(__akvm_vcpu_run)
	pushq %rbp
	mov %rsp, %rbp

	/*
	save host rflags
	save rsp to vmcs host rsp field
	load guest gprs
	vmlaunch
	save guest gprs
	restore host rflags
	*/
	push %r15
	push %r14
	push %r13
	push %r12
	push %rbx

	push %rdx
	push %rsi
	push %rdi

	/* save host rflags */
	pushfq
	popq %rbx
	mov %rbx, HOST_RFLAGS_OFFSET(%rdi)
	/* save host rsp */
	mov ASM_VMX_HOST_RSP, %rbx
	vmwrite %rsp, %rbx

	/* load guest state */
	mov GPRS_RAX_OFFSET(%rsi), %rax
	mov GPRS_RBX_OFFSET(%rsi), %rbx
	mov GPRS_RCX_OFFSET(%rsi), %rcx
	mov GPRS_RDX_OFFSET(%rsi), %rdx
	mov GPRS_RDI_OFFSET(%rsi), %rdi
	mov GPRS_RBP_OFFSET(%rsi), %rbp
	/* mov GPRS_RSP_OFFSET(%rsi), %rsp */
	mov GPRS_R8_OFFSET(%rsi),  %r8
	mov GPRS_R9_OFFSET(%rsi),  %r9
	mov GPRS_R10_OFFSET(%rsi), %r10
	mov GPRS_R11_OFFSET(%rsi), %r11
	mov GPRS_R12_OFFSET(%rsi), %r12
	mov GPRS_R13_OFFSET(%rsi), %r13
	mov GPRS_R14_OFFSET(%rsi), %r14
	mov GPRS_R15_OFFSET(%rsi), %r15
	mov GPRS_RSI_OFFSET(%rsi), %rsi

	cmpq $0, 16(%rsp)
	jz .Lvmlaunch

	UNWIND_HINT_SAVE

.Lvmresume:
	vmresume
	jmp .Lfailed
.Lvmlaunch:
	vmlaunch
.Lfailed:
	jc .Lfailedinvalid
.Lfailedvalid:
	mov $1, %rax
	jmp .Lexit
.Lfailedinvalid:
	mov $2, %rax
	jmp .Lexit

SYM_INNER_LABEL_ALIGN(akvm_vmx_vmexit, SYM_L_GLOBAL)

	UNWIND_HINT_RESTORE
	ENDBR

	/* save guest gprs */
	push %rsi
	mov 16(%rsp), %rsi
	mov %rax, GPRS_RAX_OFFSET(%rsi)
	mov %rbx, GPRS_RBX_OFFSET(%rsi)
	mov %rcx, GPRS_RCX_OFFSET(%rsi)
	mov %rdx, GPRS_RDX_OFFSET(%rsi)
	mov %rdi, GPRS_RDI_OFFSET(%rsi)
	mov %rbp, GPRS_RBP_OFFSET(%rsi)
	/* mov %rsi, GPRS_RSP_OFFSET(%rsi) */
	mov %r8,  GPRS_R8_OFFSET(%rsi)
	mov %r9,  GPRS_R9_OFFSET(%rsi)
	mov %r10, GPRS_R10_OFFSET(%rsi)
	mov %r11, GPRS_R11_OFFSET(%rsi)
	mov %r12, GPRS_R12_OFFSET(%rsi)
	mov %r13, GPRS_R13_OFFSET(%rsi)
	mov %r14, GPRS_R14_OFFSET(%rsi)
	mov %r15, GPRS_R15_OFFSET(%rsi)
	pop %rax
	mov %rax, GPRS_RSI_OFFSET(%rsi)
	mov $0, %rax

.Lexit:
	/* restore host rflags */
	mov (%rsp), %rdi
	pushq HOST_RFLAGS_OFFSET(%rdi)
	popfq

	/* clear registers with guest value */
	xor %rcx, %rcx
	xor %r8, %r8
	xor %r9, %r9
	xor %r10, %r10
	xor %r11, %r11

	pop %rdi
	pop %rsi
	pop %rdx

	pop %rbx
	pop %r12
	pop %r13
	pop %r14
	pop %r15

	pop %rbp
	RET
SYM_FUNC_END(__akvm_vcpu_run)
