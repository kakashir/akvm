#include <linux/printk.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <uapi/linux/akvm.h>
#include "common.h"


static int akvm_ioctl_run(struct file *f, unsigned int ioctl,
			   unsigned long param)
{
	FUNC_ENTRY();
	FUNC_EXIT();
	return 0;
}

static int akvm_ioctl_get_vmx_info(struct file *f, unsigned ioctl,
				    unsigned long param)
{
	FUNC_ENTRY();
	FUNC_EXIT();
	return 0;
}

static long akvm_dev_ioctl(struct file *f, unsigned int ioctl,
			   unsigned long param)
{
	int r;

	switch(ioctl) {
	case AKVM_RUN:
		r = akvm_ioctl_run(f, ioctl, param);
		break;
	case AKVM_GET_VMX_INFO:
		r = akvm_ioctl_get_vmx_info(f, ioctl, param);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

static struct file_operations akvm_dev_ops = {
	.unlocked_ioctl = akvm_dev_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice akvm_dev = {
	MISC_DYNAMIC_MINOR,
	"akvm",
	&akvm_dev_ops,
};

static int __init akvm_init(void)
{
	int r;

	r = misc_register(&akvm_dev);
	if (r)
		pr_err("akvm: failed to register device\n");

	return r;
}

static void __exit akvm_exit(void)
{
	misc_deregister(&akvm_dev);
}

module_init(akvm_init);
module_exit(akvm_exit);
MODULE_LICENSE("GPL");
