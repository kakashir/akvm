#include "mmu.h"

int akvm_handle_mmu_page_fault(struct vcpu_context *vcpu, struct mmu_context* mmu,
			       gpa fault_addr)
{
	pr_err("unimplemented: %s\n", __func__);
	return -ENOTSUPP;
}

int akvm_init_mmu(struct mmu_context *mmu, struct vm_context *vm, int level)
{
	mmu->root = __get_free_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!mmu->root)
		return -ENOMEM;

	mmu->vm = vm;
	mmu->level = level;
	INIT_LIST_HEAD(&mmu->page_list);
	return 0;
}

void akvm_deinit_mmu(struct mmu_context *mmu)
{
	free_page(mmu->root);
}
