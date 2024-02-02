#ifndef __VM_H
#define __VM_H

#include <linux/types.h>
#include <linux/idr.h>
#include "common.h"
#include "vcpu.h"

struct vm_context;
typedef void (*vcpu_destroy_notifier)(struct vm_context *vm, int vcpu_index);

struct vm_context {
	struct file *dev;
	struct mutex lock;
	struct ida vcpu_index_pool;
	vcpu_destroy_notifier vcpu_destroy_cb;
};

int akvm_create_vm(struct file *dev);

#endif
