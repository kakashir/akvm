#include <linux/list.h>
#include <asm/processor.h>
#include "mmu.h"
#include "vmx.h"
#include "vm.h"
#include "vcpu.h"

#ifdef DEBUG
#define akvm_mmu_pr_info pr_info
#else
#define akvm_mmu_pr_info(...)
#endif

#define AKVM_NULL_SPTE 0ULL
#define AKVM_MIN_GPA_ADDR 0UL
#define AKVM_MAX_GPA_ADDR vmx_ept_max_addr(&vmx_capability)

#define PAGE_LEVEL_BIT 9
#define AKVM_PAGE_SIZE(l) (1ULL << (PAGE_SHIFT + ((l) - 1) * PAGE_LEVEL_BIT))
#define AKVM_SPTE_PA_MASK (((1ULL << boot_cpu_data.x86_phys_bits) - 1) & PAGE_MASK)
#define AKVM_SPTE_COUNT (1ULL << PAGE_LEVEL_BIT)
#define AKVM_SPTE_INDEX_MASK (AKVM_SPTE_COUNT - 1)
#define AKVM_GPA_SHIFT(l) (PAGE_SHIFT + \
			   PAGE_LEVEL_BIT * ((l) - 1))
#define AKVM_GPA_MASK(l)  (~((1ULL << AKVM_GPA_SHIFT(l)) - 1))
#define AKVM_SPTE_INDEX(addr, l) (((addr) >> AKVM_GPA_SHIFT(l)) & \
				  AKVM_SPTE_INDEX_MASK)

#define AKVM_SPTE_PERM (VMX_EPT_PTE_PERM_READ |	\
			VMX_EPT_PTE_PERM_WRITE |	\
			VMX_EPT_PTE_PERM_EXE)
enum akvm_page_level {
	AKVM_PAGE_LEVEL_1 = 1,
	AKVM_PAGE_LEVEL_2, /* 2M */
	AKVM_PAGE_LEVEL_3, /* 1G */
	AKVM_PAGE_LEVEL_4, /* 512G (wo~) */
	AKVM_PAGE_LEVEL_5, /* ???G (wo~!!) */
	AKVM_PAGE_LEVEL_MAX = AKVM_PAGE_LEVEL_5,
};

typedef unsigned long spte;

struct akvm_mmu_walker {
	void *root_page;
	enum akvm_page_level max_level;
	enum akvm_page_level cur_level;
	enum akvm_page_level min_level;
	spte cur_spte;
	spte *cur_sptep;
	gpa cur_gpa;
	gpa target_gpa;
	gpa start;
	gpa end;

	spte *sptep[AKVM_MMU_MAX_LEVEL];
	gpa gpa[AKVM_MMU_MAX_LEVEL];
	bool valid;
};

struct akvm_mmu_page {
	void *page;
	enum akvm_page_level level;
	struct list_head entry;
};

struct akvm_data_page {
	struct list_head entry;
	struct page *page;
};

static inline spte* __spte_by_level(spte *p, gpa addr, enum akvm_page_level level)
{
	int index = AKVM_SPTE_INDEX(addr, level);
	return p + index;
}

static inline unsigned long __spte_to_pa(spte p)
{
	return p & AKVM_SPTE_PA_MASK;
}

static inline void* __sptep_to_va(spte *p)
{
	return __va(__spte_to_pa(*p));
}

static inline void* __spte_to_va(spte val)
{
	return __va(__spte_to_pa(val));
}

static inline struct akvm_mmu_page  *__spte_to_sub_mmu_page(spte val)
{
	unsigned long pa;

	pa = __spte_to_pa(val);
	return (void*)page_private(pfn_to_page(pa >> PAGE_SHIFT));
}

static inline bool __spte_last_level(spte val, enum akvm_page_level level)
{
	return vmx_ept_pte_large_page(val) || level == AKVM_PAGE_LEVEL_1;
}

static inline bool __spte_present(spte val)
{
	return vmx_ept_pte_present(val);
}

static inline bool __spte_at_end(spte *sptep)
{
	unsigned long spt_end = (unsigned long)sptep;

	spt_end = ALIGN(spt_end + 1, PAGE_SIZE);
	return (unsigned long)(sptep + 1) >= spt_end;
}

static void __akvm_mmu_walk_read_spte(struct akvm_mmu_walker *walker)
{
	spte* p;
	gpa target_gpa = walker->target_gpa;
	enum akvm_page_level cur_level = walker->cur_level;
	enum akvm_page_level parent_level = cur_level + 1;

	if (cur_level == walker->max_level)
		p = walker->root_page;
	else
		p = __sptep_to_va(walker->sptep[parent_level - 1]);

	walker->cur_sptep = __spte_by_level(p, target_gpa, cur_level);
	walker->sptep[cur_level - 1] = walker->cur_sptep;
	walker->cur_spte = *walker->cur_sptep;

	walker->cur_gpa = target_gpa & AKVM_GPA_MASK(cur_level);
	walker->gpa[cur_level - 1] = walker->cur_gpa;
}

static void akvm_mmu_walk_begin(struct akvm_mmu_walker *walker,
				void *root_page,
				enum akvm_page_level max_level,
				enum akvm_page_level min_level,
				gpa start, gpa end)
{
	walker->root_page = root_page;
	walker->max_level = max_level;
	walker->min_level = min_level;
	walker->cur_level = max_level;
	walker->cur_gpa = start;
	walker->target_gpa = start;
	walker->start = start;
	walker->end = end;
	walker->valid = true;

	__akvm_mmu_walk_read_spte(walker);
}

static bool akvm_mmu_walk_continue(struct akvm_mmu_walker *walker)
{
	if (!walker->valid)
		return false;

	if (walker->end <= walker->start)
		return false;

	return walker->target_gpa < walker->end &&
		walker->target_gpa >= walker->start;
}

static bool akvm_mmu_walk_down(struct akvm_mmu_walker *walker)
{
	spte val = walker->cur_spte;

	WARN_ON(walker->cur_level < walker->min_level);

	if (walker->cur_level == walker->min_level)
		return false;

	if (!vmx_ept_pte_present(val))
		return false;

	if (!__spte_to_pa(val))
		return false;

	if (vmx_ept_pte_large_page(val))
		return false;

	--walker->cur_level;
	__akvm_mmu_walk_read_spte(walker);
	return true;
}

static bool akvm_mmu_walk_side(struct akvm_mmu_walker *walker)
{
	if (__spte_at_end(walker->cur_sptep))
		return false;

	/*
	  limit the next gpa to end, thus the target_gpa will
	  stop at walker->end when return from down to up for
	  stopping travel the page table
	 */
	walker->target_gpa = min(walker->end,
				 walker->cur_gpa +
				 (1ULL << AKVM_GPA_SHIFT(walker->cur_level)));

	__akvm_mmu_walk_read_spte(walker);
	return true;
}

static bool akvm_mmu_walk_up(struct akvm_mmu_walker *walker)
{
	if (walker->cur_level == walker->max_level)
		return false;

	++walker->cur_level;
	__akvm_mmu_walk_read_spte(walker);
	return true;
}

static void akvm_mmu_walk_next(struct akvm_mmu_walker *walker)
{
	if (akvm_mmu_walk_down(walker))
		return;

	while (1) {
		if (akvm_mmu_walk_side(walker))
			return;
		if (!akvm_mmu_walk_up(walker)) {
			walker->valid = false;
			return;
		}
	}
}

static void akvm_mmu_walk_refresh(struct akvm_mmu_walker *walker)
{
	__akvm_mmu_walk_read_spte(walker);
}

#define akvm_mmu_for_each(w, r, lmax, lmin, s, e)			\
	for (akvm_mmu_walk_begin(w, r, lmax, lmin, s, e); akvm_mmu_walk_continue(w); \
	     akvm_mmu_walk_next(w))

static int akvm_mmu_create_mmu_page(struct akvm_mmu_page **new_mmu_page, int level)
{
	struct akvm_mmu_page *new;
	void *page;

	new = kzalloc(sizeof(*new), GFP_KERNEL_ACCOUNT);
	if (!new)
		return -ENOMEM;

	page = (void*)__get_free_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		goto failed_mmu_page;

	INIT_LIST_HEAD(&new->entry);
	new->level = level;
	new->page = page;
	set_page_private(pfn_to_page(__pa(page) >> PAGE_SHIFT), (unsigned long)new);

	*new_mmu_page = new;
	return 0;

failed_mmu_page:
	kfree(new);
	return -ENOMEM;
}

static void akvm_mmu_destroy_mmu_page(struct akvm_mmu_page *mmu_page)
{
	free_page((unsigned long)mmu_page->page);
	list_del(&mmu_page->entry);
	kfree(mmu_page);
}

static spte spte_init(hpa hpa, unsigned long perm, bool last_level)
{
	spte new = (hpa & AKVM_SPTE_PA_MASK) | perm;

	if (last_level && vmx_ept_mem_type_wb(&vmx_capability))
		new |= VMX_EPT_PTE_MEM_TYPE_WB;
	return new;
}

static int akvm_mmu_link_table_page(struct mmu_context *mmu,
				    struct akvm_mmu_walker *walker)
{
	int r;
	spte new_spte;
	struct akvm_mmu_page *new_page;

	r = akvm_mmu_create_mmu_page(&new_page, walker->cur_level - 1);
	if (r)
		return r;

	new_spte = spte_init(__pa(new_page->page), AKVM_SPTE_PERM, false);
	*walker->cur_sptep = new_spte;

	/* appear last better ? */
	list_add(&new_page->entry, &mmu->page_list);

	akvm_mmu_walk_refresh(walker);

	return 0;
}

static int akvm_mmu_hva_to_page(unsigned long hva, struct page **page_out)
{
	struct page *page;
	long r;

	mmap_read_lock(current->mm);
	r = pin_user_pages(hva, 1, FOLL_WRITE | FOLL_LONGTERM, &page);
	mmap_read_unlock(current->mm);
	if (r < 0)
		return r;
	if (!r)
		return -EINVAL;
	*page_out = page;
	return 0;
}

static inline void akvm_mmu_put_page(struct page *page)
{
	unpin_user_page(page);
}

static void akvm_free_data_page(struct mmu_context *mmu,
				unsigned long pa, enum akvm_page_level level)
{
	akvm_mmu_put_page(pfn_to_page(pa >> PAGE_SHIFT));
	--mmu->data_page_count;
}

static int akvm_mmu_install_data_page(struct mmu_context *mmu,
				      struct akvm_mmu_walker *walker)
{
	int r;
	int srcu_index;
	spte new_spte;
	unsigned long hva;
	struct page *page;
	struct vm_memory_slot *slot;

	srcu_index = srcu_read_lock(&mmu->vm->srcu);

	r =  akvm_vm_gpa_to_memory_slot(mmu->vm,
					walker->cur_gpa,
					walker->cur_gpa + PAGE_SIZE,
					&slot);
	if (r)
		goto release_srcu;

	hva = slot->hva + walker->target_gpa - slot->gpa;
	r = akvm_mmu_hva_to_page(hva, &page);
	if (r) {
		pr_info("%s: hva_to_page: hva:0x%lx slot->gpa:0x%lx target_gpa:0x%lx cur_gpa:0x%lx r:%d\n",
			__func__, hva, slot->gpa, walker->target_gpa, walker->cur_gpa, r);
		goto release_srcu;
	}
	new_spte = spte_init(__pa(page_address(page)), AKVM_SPTE_PERM, true);
	*walker->cur_sptep = new_spte;
	++mmu->data_page_count;

	/* pin the page now until MM notifier is handled */
	/*  akvm_mmu_put_page(page) */

release_srcu:
	srcu_read_unlock(&mmu->vm->srcu, srcu_index);

	return r;

}

static void dump_walker(struct akvm_mmu_walker *walker)
{
#ifdef DEBUG
	akvm_mmu_pr_info("%s: ml:%d cl:%d cs:0x%lx csp:0x%lx cg:0x%lx tg:0x%lx\n",
			 __func__, walker->max_level, walker->cur_level,
			 walker->cur_spte, (unsigned long)walker->cur_sptep,
			 walker->cur_gpa, walker->target_gpa);
	for (int i = walker->max_level - 1; i >= 0; --i)
		akvm_mmu_pr_info("%s:    level:%d sp:0x%lx gpa:0x%lx\n",
				 __func__, i, (unsigned long)walker->sptep[i],
				 walker->gpa[i]);
#endif
}

int akvm_handle_mmu_page_fault(struct vcpu_context *vcpu,
			       struct mmu_context* mmu, gpa fault_addr)
{
	int r;
	struct akvm_mmu_walker walker;
	enum akvm_page_level max_level = mmu->level;
	enum akvm_page_level min_level = AKVM_PAGE_LEVEL_1;
	void *root;
#if 0
	/* Test data debug purpose only */
	gpa start = ((4ULL << 12) |			\
		     (3ULL << (12 + 9)) |		\
		     (2ULL << (12 + 9 + 9)) |		\
		     (1ULL << (12 + 9 + 9 + 9)));
	gpa end = start + 1024 * PAGE_SIZE;
#else
	gpa start = fault_addr & AKVM_GPA_MASK(AKVM_PAGE_LEVEL_1);
	gpa end = start + 1;
#endif
	mutex_lock(&mmu->lock);

	root = (void*)mmu->root;
	akvm_mmu_for_each(&walker, root, max_level, min_level, start, end) {
		if (signal_pending(current)) {
			r = 1;
			break;
		}

		if (need_resched())
			cond_resched();

		dump_walker(&walker);

		if (walker.cur_level == AKVM_PAGE_LEVEL_1) {
			if (__spte_present(walker.cur_spte))
				break;

			r = akvm_mmu_install_data_page(mmu, &walker);
			if (r)
				break;
			continue;
		}

		if (!walker.cur_spte) {
			r = akvm_mmu_link_table_page(mmu, &walker);
			if (r)
				break;
			continue;
		}
	}

	mutex_unlock(&mmu->lock);

	return r;
}

static void __akvm_free_mmu_page_table(struct mmu_context *mmu,
				       void *root, enum akvm_page_level level,
				       gpa start, gpa end)
{
	struct akvm_mmu_walker walker;
	enum akvm_page_level sub_level;
	void *sub_root;
	gpa sub_start;
	gpa sub_end;
	spte spte;

	if (!root)
		return;

	akvm_mmu_for_each(&walker, root, level, level, start, end) {
		spte = walker.cur_spte;
		level = walker.cur_level;

		dump_walker(&walker);

		if (!__spte_present(spte))
			continue;

		if (__spte_last_level(spte, level)) {
			akvm_free_data_page(mmu, __spte_to_pa(spte), level);
			*walker.cur_sptep = AKVM_NULL_SPTE;
			continue;
		}

		WARN_ON(walker.cur_level == AKVM_PAGE_LEVEL_1);

		sub_level = walker.cur_level - 1;
		sub_root = __spte_to_va(spte);
		sub_start = walker.cur_gpa;
		sub_end = min(sub_start +
			      (1UL << AKVM_GPA_SHIFT(level)), end);

		__akvm_free_mmu_page_table(mmu, sub_root, sub_level,
					   sub_start, sub_end);
		akvm_mmu_destroy_mmu_page(__spte_to_sub_mmu_page(spte));
		*walker.cur_sptep = AKVM_NULL_SPTE;
	}
}

static void akvm_free_mmu_page_table(struct mmu_context *mmu,
				     gpa start, gpa end)
{
	void *root;

	mutex_lock(&mmu->lock);

	root = (void*)mmu->root;
	if (root)
		__akvm_free_mmu_page_table(mmu, root, mmu->level, start, end);

	mutex_unlock(&mmu->lock);
}

int akvm_init_mmu(struct mmu_context *mmu, struct vm_context *vm, int level)
{
	if (level > AKVM_MMU_MAX_LEVEL)
		return -EINVAL;

	mmu->root = __get_free_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!mmu->root)
		return -ENOMEM;

	mmu->vm = vm;
	mmu->level = level;
	INIT_LIST_HEAD(&mmu->page_list);
	mutex_init(&mmu->lock);
	mmu->data_page_count=0;
	return 0;
}

void akvm_deinit_mmu(struct mmu_context *mmu)
{
	akvm_free_mmu_page_table(mmu, AKVM_MIN_GPA_ADDR, AKVM_MAX_GPA_ADDR);

	WARN_ON(!list_empty(&mmu->page_list));
	WARN_ON(mmu->data_page_count);
	free_page(mmu->root);

}

unsigned long akvm_mmu_root_page(struct mmu_context *mmu,
				 struct vmx_capability *cap)
{
	unsigned long root = mmu->root;

	if (!root)
		return 0;

	WARN_ON(!vmx_ept_mem_type_wb(cap));

	root = __pa(root) & PAGE_MASK;
	root |= VMX_EPT_MEM_TYPE_WB;
	root |= (vmx_ept_level(cap) - 1) << VMX_EPT_WALK_LENGTH_SHIFT;
	if (vmx_ept_ad_bit(cap))
		root |= VMX_EPT_ENABLE_AD_BITS;

	return root;
}

void akvm_mmu_zap_memory_slot(struct mmu_context *mmu,
			      struct vm_memory_slot *slot)
{
	struct akvm_mmu_walker walker;
	struct vcpu_context *vcpu;
	enum akvm_page_level level;
	unsigned long i;
	void *root;
	spte spte;
	int flush = 0;

	mutex_lock(&mmu->lock);

	root = (void*)mmu->root;
	if (!root)
		goto unlock;

	akvm_mmu_for_each(&walker, root, mmu->level, AKVM_PAGE_LEVEL_1,
			  slot->gpa, memory_slot_gpa_end(slot)) {
		spte = walker.cur_spte;
		level = walker.cur_level;

		dump_walker(&walker);

		if (!__spte_present(spte))
			continue;

		if (!__spte_last_level(spte, level))
			continue;

		*walker.cur_sptep = AKVM_NULL_SPTE;
		akvm_free_data_page(mmu, __spte_to_pa(spte), level);
		flush = 1;
	}
unlock:
	mutex_unlock(&mmu->lock);

	if (!flush)
		return;

	akvm_vm_for_each_vcpu(mmu->vm, i, vcpu)
		akvm_vcpu_set_request(vcpu, AKVM_VCPU_REQUEST_FLUSH_TLB, true);
}
