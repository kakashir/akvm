#ifndef __MMU_H
#define __MMU_H

#include <linux/types.h>
#include <linux/mm.h>

#include "common.h"

#define AKVM_MMU_MAX_LEVEL (5)

struct vcpu_context;
struct vm_context;

struct mmu_context {
	struct vm_context *vm;

	rwlock_t lock;
	struct list_head page_list;
	unsigned long root;
	int level;
};

int akvm_init_mmu(struct mmu_context *mmu, struct vm_context *vm, int level);
void akvm_deinit_mmu(struct mmu_context *mmu);
int akvm_handle_mmu_page_fault(struct vcpu_context *vcpu, struct mmu_context* mmu,
			       gpa fault_addr);

unsigned long akvm_mmu_root_page(struct mmu_context *mmu,
				 struct vmx_capability *cap);

#endif
