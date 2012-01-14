/*
 * Here's a sample kernel module showing the use of jprobes to dump
 * the arguments of do_fork().
 *
 * For more information on theory of operation of jprobes, see
 * Documentation/kprobes.txt
 *
 * Build and insert the kernel module as done in the kprobe example.
 * You will see the trace data in /var/log/messages and on the
 * console whenever do_fork() is invoked to create a new process.
 * (Some messages may be suppressed if syslogd is configured to
 * eliminate duplicate messages.)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

/*
 * Jumper probe for do_fork.
 * Mirror principle enables access to arguments of the probed routine
 * from the probe handler.
 */

/* Proxy routine having the same arguments as actual do_fork() routine */
static long n_sys_mprotect (unsigned long start, size_t len, long prot)
{
  struct pt_regs *regs = task_pt_regs (current);
  start = regs->bx;
  len = regs->cx;
  prot = regs->dx;

  printk(KERN_INFO "start: 0x%lx len: %u prot: 0x%lx\n", start, len, prot);
  
  /* Always end with a call to jprobe_return(). */
  jprobe_return();
  return 0;
}

static struct jprobe mprotect_jprobe = {
	.entry			= n_sys_mprotect,
	.kp = {
		.symbol_name	= "sys_mprotect",
	},
};

static int __init jprobe_init(void)
{
	int ret;

	ret = register_jprobe(&mprotect_jprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
	       mprotect_jprobe.kp.addr, mprotect_jprobe.entry);
	return 0;
}

static void __exit jprobe_exit (void)
{
	unregister_jprobe(&mprotect_jprobe);
	printk(KERN_INFO "jprobe at %p unregistered\n", mprotect_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
