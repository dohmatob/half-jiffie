#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <linux/reboot.h>

static struct jprobe jp;
static int nb_times_trapped = 0;

static void dump_state (struct pt_regs *regs)
{
  printk (KERN_INFO "\nSTACK DUMP\n");
  printk (KERN_INFO "ip at 0x%08lx", regs->ip);
  printk (KERN_INFO "ax: 0x%08lx, bx: 0x%08lx, cx: 0x%08lx, dx: 0x%08lx\n", regs->ax, regs->bx, regs->cx, regs->dx);
}

static long n_sys_mprotect (ulong start, size_t len, ulong prot)
{
  nb_times_trapped++;
  dump_state (task_pt_regs (current));
  printk (KERN_INFO "mprotect'ing address space from 0x%lx through 0x%lx with protection %lx\n", start, start + len, prot);
  
  jprobe_return ();
  return 0;
}

static void n_native_write_cr0 (ulong val)
{
  nb_times_trapped++;
  dump_state (task_pt_regs (current));
  printk (KERN_INFO "the 16th bit of tha value to be written in cr0 is %01lx\n", (val & (1 << 16)) >> 16);
  
  if (!(val & (1 << 16)))
    {
      printk (KERN_EMERG "bad people 'em wanna do us ill!"); 
      emergency_restart ();
    } 
  jprobe_return ();
}

static int __init jprobe_init (void)
{
  jp.kp.symbol_name = "native_write_cr0";
  jp.entry = n_native_write_cr0;

  if (register_jprobe (&jp) < 0) 
    {
      printk (KERN_INFO "register_jprobe failed for %s\n", jp.kp.symbol_name);
      return 1;
    }

  printk (KERN_INFO "registered jprobe for %s\n", jp.kp.symbol_name);

  return 0;
}

static void __exit jprobe_exit (void)
{
  unregister_jprobe (&jp);
  printk (KERN_INFO "unregistered jprobe for %s\n", jp.kp.symbol_name);
  printk (KERN_INFO "trapped %d times ..\n", nb_times_trapped);
}

module_init (jprobe_init);
module_exit (jprobe_exit);
MODULE_LICENSE ("GPL");
