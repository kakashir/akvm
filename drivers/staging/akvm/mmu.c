#include <linux/list.h>

#include "mmu.h"
#include "vmx.h"
#include "vm.h"

#ifdef DEBUG
#define akvm_mmu_pr_info pr_info
#else
#define akvm_mmu_pr_info(...)
#endif

#define PAGE_LEVEL_BIT 9
#define AKVM_PAGE_SIZE(l) (1ULL << (PAGE_SHIFT + ((l) - 1) * PAGE_LEVEL_BIT))
/* TODO: not all high bits are VALID physical address! */
#define AKVM_SPTE_PA_MASK ~((1ULL << PAGE_SHIFT) - 1)
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
	spte cur_spte;
	spte *cur_sptep;
	gpa cur_gpa;
	gpa target_gpa;
	gpa start;
	gpa end;

	spte *sptep[AKVM_MMU_MAX_LEVEL];
	gpa gpa[AKVM_MMU_MAX_LEVEL];
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

static inline bool __spte_last_level(spte val, enum akvm_page_level level)
{
	return vmx_ept_pte_large_page(val) || level == AKVM_PAGE_LEVEL_1;
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
				void *root_page, enum akvm_page_level max_level,
				gpa start, gpa end)
{
	walker->root_page = root_page;
	walker->max_level = max_level;
	walker->cur_level = max_level;
	walker->cur_gpa = start;
	walker->target_gpa = start;
	walker->start = start;
	walker->end = end;

	__akvm_mmu_walk_read_spte(walker);
}

static bool akvm_mmu_walk_continue(struct akvm_mmu_walker *walker)
{
	return walker->target_gpa < walker->end;
}

static bool akvm_mmu_walk_down(struct akvm_mmu_walker *walker)
{
	spte val = walker->cur_spte;

	WARN_ON(walker->cur_level < AKVM_PAGE_LEVEL_1);

	if (walker->cur_level == AKVM_PAGE_LEVEL_1)
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

	walker->target_gpa = walker->cur_gpa +
		(1ULL << AKVM_GPA_SHIFT(walker->cur_level));

	if (!akvm_mmu_walk_continue(walker))
		return false;
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
	if (akvm_mmu_walk_side(walker))
		return;

	while (1) {
		if (!akvm_mmu_walk_up(walker))
			return;
		if (akvm_mmu_walk_side(walker))
			return;
	}
}

static void akvm_mmu_walk_refresh(struct akvm_mmu_walker *walker)
{
	__akvm_mmu_walk_read_spte(walker);
}

#define akvm_mmu_for_each(w, r, l, s, e)		\
	for (akvm_mmu_walk_begin(w, r, l, s, e); akvm_mmu_walk_continue(w); \
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

static int akvm_mmu_install_data_page(struct mmu_context *mmu,
				      struct akvm_mmu_walker *walker)
{
	int r;
	spte new_spte;
	unsigned long hva;
	struct page *page;
	struct vm_memory_slot *slot;
	struct akvm_data_page *data_page;

	data_page = kzalloc(sizeof(*data_page), GFP_KERNEL_ACCOUNT);
	INIT_LIST_HEAD(&data_page->entry);

	r =  akvm_vm_gpa_to_memory_slot(mmu->vm,
					walker->cur_gpa,
					walker->cur_gpa + PAGE_SIZE,
					&slot);
	if (r)
		goto free_data_page_struct;

	hva = slot->hva + walker->target_gpa - slot->gpa;
	r = akvm_mmu_hva_to_page(hva, &page);
	if (r)
		goto free_data_page_struct;

	new_spte = spte_init(__pa(page_address(page)), AKVM_SPTE_PERM, true);
	*walker->cur_sptep = new_spte;

	data_page->page = page;
	list_add(&data_page->entry, &mmu->data_page_list);
	/* pin the page */
	// akvm_mmu_put_page(page);

	return r;

free_data_page_struct:
	kfree(data_page);
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
	void *root = (void*)akvm_mmu_root_page(mmu);
#if 0
	/* Test data debug purpose only */
	gpa start = ((4ULL << 12) |			\
		     (3ULL << (12 + 9)) |		\
		     (2ULL << (12 + 9 + 9)) |		\
		     (1ULL << (12 + 9 + 9 + 9)));
	gpa end = start + 1024 * PAGE_SIZE;
#else
	gpa start = fault_addr;
	gpa end = fault_addr + PAGE_SIZE;
#endif
	write_lock(&mmu->lock);

	akvm_mmu_for_each(&walker, root, max_level, start, end) {
		if (signal_pending(current)) {
			r = 1;
			break;
		}

		if (need_resched())
			cond_resched();

		dump_walker(&walker);

		if (walker.cur_level == AKVM_PAGE_LEVEL_1) {
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

	write_unlock(&mmu->lock);
	return r;
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
	INIT_LIST_HEAD(&mmu->data_page_list);
	rwlock_init(&mmu->lock);

	return 0;
}

void akvm_deinit_mmu(struct mmu_context *mmu)
{
	struct akvm_mmu_page *cur;
	struct akvm_mmu_page *tmp;
	struct akvm_data_page *cur_data;
	struct akvm_data_page *tmp_data;

	list_for_each_entry_safe(cur, tmp, &mmu->page_list, entry)
		akvm_mmu_destroy_mmu_page(cur);

	list_for_each_entry_safe(cur_data, tmp_data, &mmu->data_page_list,
				 entry) {
		akvm_mmu_put_page(cur_data->page);
		kfree(cur_data);
	}

	free_page(mmu->root);
}
