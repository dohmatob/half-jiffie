#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

static struct kretprobe krp;

static int entry_handler (struct kretprobe_instance *instance, struct pt_regs *regs)
{
  write_cr0 (read_cr0 () & ~(0x10000)); 
  return 0;
}

static int ret_handler (struct kretprobe_instance *instance, struct pt_regs *regs)
{
  int ret_val = (int) regs->ax;
  
  if (ret_val < 0)
    {
      printk("failed\n");
      return -1;
    }

  printk("passed; fd = %d\n", ret_val);
  return 0;
}

static int __init kretprobe_init (void)
{
  krp.kp.symbol_name = "sys_open";
  krp.entry_handler = entry_handler;
  krp.handler = ret_handler;

  register_kretprobe (&krp);
  printk("registered\n");

  return 0;
}

static void __exit kretprobe_exit (void)
{
  unregister_kretprobe (&krp);
  printk("done\n");
}

module_init (kretprobe_init);
module_exit (kretprobe_exit);
MODULE_LICENSE ("GPL");
