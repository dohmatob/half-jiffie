#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/reboot.h>

long  n_sys_mprotect (unsigned long start, size_t len, unsigned long prot)
{
  printk("mprotect'ing address space from 0x%lx through 0x%lx with protection 0x%lx\n", start, start + len, prot);
  jprobe_return ();

  return 0;
}

static struct jprobe sys_mprotect_jprobe =
  {
    .entry = n_sys_mprotect,
    .kp = 
    {
      .symbol_name = "sys_mprotect"
    }
  };

static int __init jprobe_init (void)
{
  int ret;

  if((ret = register_jprobe (&sys_mprotect_jprobe)) < 0)
    {
      printk("register_jprobe failed for sys_mprotect!\n");
      return -1;
    }

  printk("planted jprobe for sys_mprotect at %p, handler at %p\n", sys_mprotect_jprobe.kp.addr, sys_mprotect_jprobe.entry);

  return 0;
}

static void __exit jprobe_exit (void)
{
  unregister_jprobe(&sys_mprotect_jprobe);
  printk("jprobe for sys_mprotect at %p unregistered!\n", sys_mprotect_jprobe.kp.addr);
}

module_init (jprobe_init);
module_exit (jprobe_exit);
MODULE_LICENSE ("GPL");

  
