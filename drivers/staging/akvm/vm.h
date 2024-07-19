#ifndef __VM_H
#define __VM_H

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/xarray.h>
#include <linux/interval_tree.h>
#include <linux/list.h>
#include "common.h"
#include "mmu.h"

struct vcpu_context;
struct vm_context;

typedef void (*vcpu_destroy_notifier)(struct vm_context *vm, int vcpu_index);
typedef int (*vcpu_create_notifier)(struct vm_context *vm, int vcpu_index,
				     struct vcpu_context *vcpu);

#define VM_MEM_ROOT_HVA 0
#define VM_MEM_ROOT_GPA 1
#define VM_MEM_ROOT_NUM 2
struct vm_memory_slot {
	struct interval_tree_node node[VM_MEM_ROOT_NUM];
	struct list_head entry;

	unsigned long hva;
	unsigned long gpa;
	unsigned long size;
	unsigned long flags;
};
#define memory_slot_gpa_end(ms) ((ms)->gpa + (ms)->size)

struct vm_memory_space {
	struct rb_root_cached root[VM_MEM_ROOT_NUM];
	struct list_head slot_list;
};

struct vm_context {
	struct file *dev;
	struct mutex lock;
	struct srcu_struct srcu;
	struct ida vcpu_index_pool;
	struct xarray vcpus;

	struct mmu_context mmu;
	struct vm_memory_space __rcu *memory;

	vcpu_create_notifier vcpu_create_cb;
	vcpu_destroy_notifier vcpu_destroy_cb;
};

int akvm_create_vm(struct file *dev);
int akvm_vm_gpa_to_memory_slot(struct vm_context *vm,
			       gpa gpa_addr, gpa gpa_end,
			       struct vm_memory_slot **slot);
#define akvm_vm_for_each_vcpu(vm, i, vcpu) \
	xa_for_each(&vm->vcpus, i, vcpu)
#endif
