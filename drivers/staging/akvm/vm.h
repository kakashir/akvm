#ifndef __VM_H
#define __VM_H

#include <linux/types.h>
#include "common.h"

struct vm_context {
	struct file *dev;
};

int akvm_create_vm_fd(struct vm_context *vm, struct file *dev);

#endif
