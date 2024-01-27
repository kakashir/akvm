#include <linux/printk.h>
#include <linux/module.h>

#define __FUNC_TRACE__(text) pr_info("%s() " #text "\n", __func__);
#define FUNC_ENTRY  __FUNC_TRACE__("ENTRY")
#define FUNC_EXIT  __FUNC_TRACE__("EXIT")

static int __init akvm_init(void)
{
	FUNC_ENTRY;

	FUNC_EXIT;

	return 0;
}

static void __exit akvm_exit(void)
{
	FUNC_ENTRY;
	FUNC_EXIT;
}

module_init(akvm_init);
module_exit(akvm_exit);
MODULE_LICENSE("GPL");
