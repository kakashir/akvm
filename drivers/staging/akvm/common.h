#ifndef _AKVM_COMMON_H_
#define _AKVM_COMMON_H_

#include <linux/types.h>
#include <linux/preempt.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include "vmx.h"

#define __FUNC_TRACE__(text) pr_info("%s() " #text "\n", __func__);
#define FUNC_ENTRY()  __FUNC_TRACE__("ENTRY")
#define FUNC_EXIT()  __FUNC_TRACE__("EXIT")

extern struct vmx_capability vmx_capability;
extern struct preempt_ops akvm_preempt_ops;
DECLARE_PER_CPU(struct vmx_region *, vmx_region);

struct vmcs_list {
	struct list_head head;
};
DECLARE_PER_CPU(struct vmcs_list, vmcs_list);

#endif
