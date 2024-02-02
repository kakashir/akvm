#ifndef __VM_H
#define __VM_H

#include <linux/types.h>
#include <linux/idr.h>
#include <linux/xarray.h>
#include "common.h"

struct vcpu_context;
struct vm_context;

typedef void (*vcpu_destroy_notifier)(struct vm_context *vm, int vcpu_index);
typedef int (*vcpu_create_notifier)(struct vm_context *vm, int vcpu_index,
				     struct vcpu_context *vcpu);

struct vm_context {
	struct file *dev;
	struct mutex lock;
	struct ida vcpu_index_pool;
	struct xarray vcpus;

	vcpu_create_notifier vcpu_create_cb;
	vcpu_destroy_notifier vcpu_destroy_cb;
};

int akvm_create_vm(struct file *dev);

#endif
