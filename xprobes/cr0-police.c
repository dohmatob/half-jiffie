#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

static inline void __set_cr0 (unsigned long val)
{
  __asm__ volatile ("mov %0, %%cr0 \t\n"
                    : : "r" (val), "m" (__force_order));
}

static inline unsigned long __get_cr0 (void)
{
  unsigned long res;
  __asm__ volatile ("mov %%cr0, %0 \t\n"
		    : "=r" (res), "=m" (__force_order));

  return res;
}

static inline unsigned long __get_cr4 (void)
{
  unsigned long res;
  __asm__ volatile ("mov %%cr4, %0 \t\n"
                    : "=r" (res), "=m" (__force_order));
                    
  return res;
}

static inline void __set_cr4 (unsigned long val)
{
  __asm__ volatile ("mov %0, %%cr4 \t\n"
                    : : "r" (val), "m" (__force_order));
}

#define __disnable_cr0_WP() (__set_cr0 (__get_cr0 () & (~(0x1 << 16))))
#define __enable_cr0_WP() (__set_cr0 (__get_cr0 () | (0x1 << 16)))

static int nb_times_probed;
static short int restore;

struct jprobe jp;
struct kretprobe krp;

static void j_native_write_cr0 (unsigned long val)
{ 
  nb_times_probed++;  
  if (!(val & (0x1 << 16)))
    {
      printk ("blackhat're hackin' on CR0; piss 'em off!\n");
      restore++;
    }
    
  jprobe_return ();   
}

static int kret_handler (struct kretprobe_instance *ri, struct pt_regs *regs)
{
  nb_times_probed++;
  if (restore == 1)
    {
      printk ("restorin' CR0 ..\n");
      __enable_cr0_WP ();
      restore--;
    }
    
  return 0;
}

  


static int __init inject (void)
{
  nb_times_probed = 0;
  restore = 0;
  jp.kp.symbol_name = krp.kp.symbol_name =  "native_write_cr0";
  jp.entry = j_native_write_cr0;
  krp.handler = kret_handler;
  
  if (register_jprobe (&jp) < 0)
  {
     printk ("register_jprobe failed for %s\n", jp.kp.symbol_name);
     return 1;
  }
  
  printk ("planted jprobe for %s at 0x%lx\n", jp.kp.symbol_name, (unsigned long) jp.kp.addr);
  if (register_kretprobe (&krp) < 0)
    {
      printk ("register_kretprobe failed for %s\n", krp.kp.symbol_name);
      return 1;
    }
    
  printk ("kretprobe for %s planted at 0x%lx\n", jp.kp.symbol_name, (unsigned long)jp.kp.addr);

  return 0;
}

static void __init eject (void)
{
  unregister_jprobe (&jp);
  printk ("unplanted jprobe at 0x%lx\n", (unsigned long)jp.kp.addr);
  
  unregister_kretprobe (&krp);
  printk ("unplanted kretprobe at 0x%lx\n", (unsigned long)krp.kp.addr);
  
  printk ("probed %d times ..\n", nb_times_probed);
}

module_init (inject);
module_exit (eject);
MODULE_LICENSE ("GPL");
