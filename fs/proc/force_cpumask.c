// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cpumask.h>

#include "internal.h"

extern void get_force_cpumask(struct cpumask *mask);
extern void set_force_cpumask(const struct cpumask *new);

static ssize_t force_cpumask_proc_write(struct file *file, const char __user *ubuf,
					size_t size, loff_t *offset)
{
	ssize_t ret;
	struct cpumask new;

	ret = cpumask_parselist_user(ubuf, size, &new);
	if (ret) {
		pr_err("failed to parse cpumask list:%ld\n", ret);
		return ret;
	}

	pr_info("Set force cpumask to:%*pbl\n", cpumask_pr_args(&new));
	set_force_cpumask(&new);

	return size;
}

static ssize_t force_cpumask_proc_read(struct file *file, char __user *ubuf,
				       size_t nbytes, loff_t *ppos)
{
	ssize_t cp_size;
	char buf[16];
	struct cpumask current_mask;

	get_force_cpumask(&current_mask);
	cp_size = cpumap_print_list_to_buf(buf, &current_mask,
					   *ppos, sizeof(buf));
	if (cp_size > 0) {
		if (copy_to_user(ubuf, buf, cp_size))
			return -EFAULT;
	} else if (!cp_size) {
		put_user('\n', ubuf);
		cp_size = 1;
	} else {
		cp_size = 0;
	}

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
