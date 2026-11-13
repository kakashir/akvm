// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include "internal.h"

extern void set_force_cpumask_index(int index);
extern int get_force_cpumask_index(void);

struct opt_map {
	const char *str;
	int opt;
};

static struct opt_map str_to_opt[] = {
	{.str = "pcore\n", .opt = FORCE_CPUMASK_PCORE},
	{.str = "ecore\n", .opt = FORCE_CPUMASK_ECORE},
	{.str = "lecore\n", .opt = FORCE_CPUMASK_LECORE},
	{.str = "all\n", .opt = FORCE_CPUMASK_ALL},
	{.str = NULL, .opt = 0},
};

static ssize_t force_cpumask_proc_write(struct file *file, const char __user *ubuf,
					size_t size, loff_t *offset)
{
	char *buf;
	int i = 0;

	buf = kmalloc(size + 1, GFP_KERNEL_ACCOUNT);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, ubuf, size)) {
		pr_info("failed to copy user content\n");
		return -EINVAL;
	}
	buf[size] = 0;


	while(str_to_opt[i].str) {
		if (sysfs_streq(str_to_opt[i].str, buf))
			break;
		++i;
	}

	if (str_to_opt[i].str) {
		pr_info("Set force cpumask to:%s\n", str_to_opt[i].str);
		set_force_cpumask_index(str_to_opt[i].opt);
	}

	kfree(buf);
	return size;
}

static ssize_t force_cpumask_proc_read(struct file *file, char __user *buf,
				       size_t nbytes, loff_t *ppos)
{
	int cur_index = get_force_cpumask_index();
	int  i;
	const char *str = NULL;
	size_t cp_size;

	for(i = 0; str_to_opt[i].str; ++i) {
		if (str_to_opt[i].opt == cur_index) {
			str = str_to_opt[i].str;
			break;
		}
	}

	if (!str)
		return 0;

	cp_size = min(strlen(str + *ppos), nbytes);
	if (copy_to_user(buf, str + *ppos, cp_size))
		return -EFAULT;

	*ppos += cp_size;
	return cp_size;
}

static const struct proc_ops force_cpumask_proc_ops = {
	.proc_read = force_cpumask_proc_read,
	.proc_write = force_cpumask_proc_write,
};

static int __init proc_force_cpumask_init(void)
{
	struct proc_dir_entry *pde;

	pde = proc_create("force_cpumask", 0666, NULL, &force_cpumask_proc_ops);
	if (pde)
		pde_make_permanent(pde);
	else
		pr_info("%s: failed\n", __func__);
	return 0;
}
fs_initcall(proc_force_cpumask_init);
