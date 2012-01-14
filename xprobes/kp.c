#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

static int nb_times_trapped = 0;
struct kprobe kp;

int pre_handler (struct kprobe *p, struct pt_regs *regs)
{
  printk ("pre_handler: p->addr = 0x%p, flags = 0x%lx\n", p->addr, regs->flags);
  printk ("%s trapped %d times ..\n", p->symbol_name, ++nb_times_trapped);
  return 0;
}

void post_handler (struct kprobe *p, struct pt_regs *regs, ulong flags)
{
  printk("post_handler: p->addr = 0x%p, flags = 0x%lx\n", p->addr, regs->flags);
}

int fault_handler (struct kprobe *p, struct pt_regs *regs, int trapnr)
{
  printk("fault_handler: p->addr = 0x%p, flags = 0x%lx\n", p->addr, regs->flags);

  return 0;
}

static int __init kp_init (void)
{
  kp.symbol_name = "sys_ioctl";
  kp.pre_handler = pre_handler;
  kp.post_handler = post_handler;
  kp.fault_handler = fault_handler;

  register_kprobe (&kp);
  printk("registered\n");

  return 0;
}

static void __exit kp_exit (void)
{
  unregister_kprobe (&kp);
  printk("unregistered\n");
}

module_init (kp_init);
module_exit (kp_exit);
MODULE_LICENSE("GPL");
