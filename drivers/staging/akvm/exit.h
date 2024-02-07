#ifndef __EXIT_H
#define __EXIT_H

#include <linux/types.h>
#include "vcpu.h"

int handle_vm_exit(struct vcpu_context *vcpu);
int handle_vm_exit_irqoff(struct vcpu_context *vcpu);

#endif
