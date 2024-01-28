/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>

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
#define RFLAGS_OFFSET (16 * WORD_SIZE)

#define ASM_VMX_HOST_RSP $0x6c14

SYM_FUNC_START(__akvm_vcpu_run)
	pushq %rbp
	mov %rsp, %rbp

	/*
	save rsp to vmcs host rsp field
	save host gprs
	load guest gprs
	vmlaunch
	save guest gprs
	restore host gprs
	*/

	/* save param3: launched */
	pushq %rdx
	pushq %rsi
	pushq %rdi

	/* save host rflags */
	pushfq
	popq %rax
	mov %rax, RFLAGS_OFFSET(%rdi)

	/* save host gprs */
	mov %rax, GPRS_RAX_OFFSET(%rdi)
	mov %rbx, GPRS_RBX_OFFSET(%rdi)
	mov %rcx, GPRS_RCX_OFFSET(%rdi)
	mov %rdx, GPRS_RDX_OFFSET(%rdi)
	mov %rdi, GPRS_RDI_OFFSET(%rdi)
	mov %rsi, GPRS_RSI_OFFSET(%rdi)
	mov %rbp, GPRS_RBP_OFFSET(%rdi)
	mov %rsp, GPRS_RSP_OFFSET(%rdi)
	mov %r8,  GPRS_R8_OFFSET(%rdi)
	mov %r9,  GPRS_R9_OFFSET(%rdi)
	mov %r10, GPRS_R10_OFFSET(%rdi)
	mov %r11, GPRS_R11_OFFSET(%rdi)
	mov %r12, GPRS_R12_OFFSET(%rdi)
	mov %r13, GPRS_R13_OFFSET(%rdi)
	mov %r14, GPRS_R14_OFFSET(%rdi)
	mov %r15, GPRS_R15_OFFSET(%rdi)

	/* save host rsp */
	movq ASM_VMX_HOST_RSP, %rax
	vmwrite %rsp, %rax

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
	jz _vmlaunch
	jmp _vmresume
_vmlaunch:
	vmlaunch
	jmp _after_run
_vmresume:
	vmresume
_after_run:
	/* kind of vmentry failure here */
	jc _failedinvalid
	jz _failed
	movq $3, %rax
	jmp _exit
_failed:
	movq $1, %rax
	jmp _exit
_failedinvalid:
	movq $2, %rax
	jmp _exit
SYM_INNER_LABEL_ALIGN(akvm_vmx_vmexit, SYM_L_GLOBAL)
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

_exit:
	/* restore host state */
	mov (%rsp), %rdi
	/* mov GPRS_RAX_OFFSET(%rdi), %rax */
	mov GPRS_RBX_OFFSET(%rdi), %rbx
	mov GPRS_RCX_OFFSET(%rdi), %rcx
	/* mov GPRS_RDX_OFFSET(%rdi), %rdx */
	/* mov GPRS_RSI_OFFSET(%rdi), %rsi */
	mov GPRS_RBP_OFFSET(%rdi), %rbp
	mov GPRS_R8_OFFSET(%rdi),  %r8
	mov GPRS_R9_OFFSET(%rdi),  %r9
	mov GPRS_R10_OFFSET(%rdi), %r10
	mov GPRS_R11_OFFSET(%rdi), %r11
	mov GPRS_R12_OFFSET(%rdi), %r12
	mov GPRS_R13_OFFSET(%rdi), %r13
	mov GPRS_R14_OFFSET(%rdi), %r14
	mov GPRS_R15_OFFSET(%rdi), %r15
	/* mov GPRS_RDI_OFFSET(%rdi), %rdi */

	/* restore host rflags */
	mov RFLAGS_OFFSET(%rdi), %rdx
	pushq %rdx
	popfq

_final_exit:
	popq %rdx
	popq %rdi
	popq %rsi
	popq %rbp
	retq
SYM_FUNC_END(__akvm_vcpu_run)
