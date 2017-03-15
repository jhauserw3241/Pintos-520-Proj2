#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

struct exec_info
{
	const char *file_name;
	struct semaphore load_done;
	struct wait_status *wait_status;
	bool success;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
	printf("Start process_execute\n");
	printf("File name: %s\n", file_name);


	char *fn_copy;
  tid_t tid;
	char *save_ptr, *pname;
	char thread_name[16];
	struct exec_info exec;

	exec.file_name = file_name;
	sema_init(&exec.load_done, 0);

	strlcpy(thread_name, file_name, sizeof thread_name);
  strtok_r(thread_name, " ", &save_ptr);

	printf("Thread name: %s\n", thread_name);

	tid = thread_create(thread_name, PRI_DEFAULT, start_process, &exec);
	if(tid != TID_ERROR)
	{
		sema_down (&exec.load_done);
		if (exec.success)
		 list_push_back(&thread_current()->children, &exec.wait_status->elem);
		else
		 tid = TID_ERROR;
	}


  ///* Make a copy of FILE_NAME.
  //   Otherwise there's a race between the caller and load(). */
  //fn_copy = palloc_get_page (0);
  //if (fn_copy == NULL)
  //  return TID_ERROR;
  //strlcpy (fn_copy, file_name, PGSIZE);

	//pname = strtok_r(file_name, " ", &save_ptr);

	//strlcpy(thread_name, file_name, sizeof thread_name);
	//strtok_r(thread_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  //tid = thread_create (pname, PRI_DEFAULT, start_process, fn_copy);
  //tid = thread_create (thread_name, PRI_DEFAULT, start_process, );
  //if (tid == TID_ERROR)
  //  palloc_free_page (fn_copy);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *exec_)
{

	printf("Start start_process\n");
	struct exec_info *exec = exec_;

	printf("File name: %s\n", exec->file_name);

//  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
	//char *save_ptr;

	//file_name = strtok_r(execfile_name, " ", &save_ptr);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (exec->file_name, &if_.eip, &if_.esp);

	printf("Is process loading succesfully? %d\n", success);


	///* Initialize interrupt frame and load executable */
	//memset(&if_, 0, sizeof if_);
	//if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	//if_.cs = SEL_UCSEG;
	//if_.eflags = FLAG_IF | FLAG_MBS;
	//success = load(exec->file_name, &if_.eip, &if_.esp);

	if(success)
	{
		exec->wait_status = thread_current()->wait_status = malloc(sizeof *exec->wait_status);
		success = exec->wait_status != NULL;
	}

	printf("Hello\n");

	if(success)
	{
		printf("Before lock creation\n");
	  lock_init(&exec->wait_status->lock);
		printf("After lock creation\n");
	  exec->wait_status->ref_cnt = 2;
		printf("Before grab tid\n");
	  exec->wait_status->tid = thread_current()->tid;
	  exec->wait_status->exit_code = -1;
		sema_init(&exec->wait_status->dead, 0);
		printf("After sucess handling\n");
	}

	printf("Middle of start_process\n");

	exec->success = success;
	sema_up(&exec->load_done);

	printf("Almost %d\n", success);

	if(!success)
		thread_exit();

	printf("End of processing in start_process\n");

  ///* If load failed, quit. */
  //palloc_free_page (exec->file_name);
  //if (!success)
  //  thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  printf("Almost there\n");
	NOT_REACHED ();
	printf("End of start process\n");
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	printf("Start process_wait\n");
	struct thread *c = thread_current();
	struct list_elem *child;

	for(child = list_begin(&c->children);child != list_end(&c->children); child = list_next(child))
	{
		struct wait_status *cs = list_entry(child, struct wait_status, elem);
		if(cs->tid == child_tid)
		{
			int exit;
			list_remove(child);
			sema_down(&cs->dead);
			exit = cs->exit_code;
			delete_child(cs);
			return exit;
		}
	}

  return -1;
}

void delete_child(struct wait_status *cs);

/* Delete child from list of children waiting to run */
void
delete_child(struct wait_status * cs)
{
	int new_ref_cnt;

	lock_acquire(&cs->lock);
	new_ref_cnt = --cs->ref_cnt;
	lock_release(&cs->lock);

	if(new_ref_cnt == 0)
		free(cs);
}

/* Free the current process's resources. */
void
process_exit (void)
{
	printf("Start process_exit\n");
  struct thread *cur = thread_current ();
  uint32_t *pd;
	struct list_elem *e, *next;

	/* Close executable */
	file_close(cur->bin_file);

	/* Notify parent that the child died */
	if(cur->wait_status != NULL)
	{
		struct wait_status *cs = cur->wait_status;
		printf("%s: exit(%d)\n", cur->name, cs->exit_code);
		sema_up(&cs->dead);
		delete_child(cs);
	}

	/* Free entries of children list */
	for(e = list_begin(&cur->children); e != list_end(&cur->children); e = next)
	{
		struct wait_status *cs = list_entry(e, struct wait_status, elem);
		next = list_remove(e);
		delete_child(cs);
	}

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
	// Adding print statements in this function will break the program
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmdline, void (**eip) (void), void **esp)
{
	printf("Start load\n");

	printf("Command string: %s\n", cmdline);

  struct thread *t = thread_current ();
	char file_name[NAME_MAX + 2];
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
	char *cp;

	printf("Before allocate page dir\n");

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

	printf("Before extract file_name\n");

	/* Extract file_name from command line */
	while(*cmdline == ' ')
		cmdline++;
	strlcpy(file_name, cmdline, sizeof file_name);
	cp = strchr(file_name, ' ');
	if(cp != NULL)
		*cp = '\0';

	printf("Before open executable\n");

  /* Open executable file. */
  file = filesys_open (file_name);
	printf("File name: %s\n", file_name);

  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }
	file_deny_write(file);

	printf("After open executable\n");

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

	printf("Right before setup_stack\n");
  /* Set up stack. */
  if (!setup_stack (esp, cmdline))
    goto done;

	//printf("Successfully setup stack\n");
	hex_dump(0, *esp, (int)((size_t) PHYS_BASE - (size_t) *esp), true);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
	printf("Load sucessful\n");
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
 		 it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create functions to help with setting up the stack */
static void reverse(int argc, char ** argv);
static void * push(uint8_t *kpage, size_t *ofs, const void *buf, size_t size);
static bool init_cmd_line(uint8_t *kpage, uint8_t *upage, const char *cmd_line, void **esp);

static void
reverse(int argc, char **argv)
{
	for(; argc>1; argc -=2, argv++)
	{
		char *tmp = argv[0];
		argv[0] = argv[argc-1];
		argv[argc-1] = tmp;
	}
	return;
}

static void *
push(uint8_t *kpage, size_t *ofs, const void *buf, size_t size)
{
	size_t padsize = ROUND_UP(size, sizeof(uint32_t));
	if(*ofs < padsize)
		return NULL;

	*ofs -= padsize;
	memcpy(kpage + *ofs + (padsize - size), buf, size);
	return kpage + *ofs + (padsize - size);
}

static bool
init_cmd_line(uint8_t *kpage, uint8_t *upage, const char *cmd_line, void **esp)
{

	size_t ofs = PGSIZE;
	char *const null = NULL;
	char *cmd_line_copy;
	char *karg, *saveptr;
	int argc;
	char **argv;

	/* Push command line string. */

	cmd_line_copy = push(kpage, &ofs, cmd_line, strlen(cmd_line) + 1);
	if(cmd_line_copy == NULL)
		return false;

	if(push(kpage, &ofs, &null, sizeof null) == NULL)
		return false;


	/* Parse command line into arguments
	  and push them in reverse order */

	argc = 0;
	for(karg = strtok_r(cmd_line_copy, " ", &saveptr); karg != NULL;
			karg = strtok_r(NULL, " ", &saveptr))
	{
		void *uarg = upage + (karg - (char *)kpage);
		if(push(kpage, &ofs, &uarg, sizeof uarg) == NULL)
			return false;
		argc++;
	}


	/* Reverse the order of the command line arguments. */

	argv = (char **)(upage + ofs);
	reverse(argc, (char **)(kpage + ofs));

	/* Push argv, argc, "return address". */

	if(push(kpage, &ofs, &argv, sizeof argv) == NULL
		|| push(kpage, &ofs, &argc, sizeof argc) == NULL
	  || push(kpage, &ofs, &null, sizeof null) == NULL)
			return false;

	/* Set initial stack pointer */
	//memcpy(*esp, &null, sizeof null);

	*esp = upage + ofs;
	return true;
  // Initial argv_size | Will be incremented as needed
	/*
  int argv_size = 2;
  int argc = 0;
  char ** argv = malloc (argv_size * sizeof(char *));

  for (token = strtok_r (cmd_line, " ", &save_ptr); token!= NULL;
      token = strtok_r (NULL, " ", &save_ptr))
  {
    *esp -= strlen(token) + 1;
    argv[argc] = *esp;
    argc++;

    if (argc >= 64)
    {
      free(argv);
      return false;
    }


    if (argc >= argv_size)
    {
      argv_size *= 2;
      argv = realloc(argv,argv_size* sizeof(char *));
    }

    memcpy(*esp,token,strlen(token) + 1);

  }

  argv[argc] = 0;

  int i = 0;
  for (i = argc; i >= 0; i--)
  {
    *esp -= sizeof(char*);
    memcpy(*esp,&argv[i],sizeof(char*));

  }*/

  //pushing argv
	/*
  karg = *esp;
  *esp-=sizeof(char**);
  memcpy(*esp,&karg,sizeof(char**));

  // Pushing argc
  *esp -= sizeof(int);
  memcpy(*esp,&argc,sizeof(int));

  // Pushing fake return address
  *esp -= sizeof(null);
  memcpy(*esp, &null,sizeof(null));
  free(argv);
	*esp = upage + ofs;
	return true;*/

  //hex_dump(PHYS_BASE,*esp,PHYS_BASE-(*esp),true);
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *file_name)
{
	printf("Start setup_stack\n");

  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
			uint8_t *upage = ((uint8_t *)PHYS_BASE) - PGSIZE;
      success = install_page (upage, kpage, true);
      if (success)
        //*esp = PHYS_BASE;
				success = init_cmd_line(kpage, upage, file_name, esp);
      else
        palloc_free_page (kpage);
    }


	/*// Inspiration goes here
	char *cmd;
	char *save_ptr;
	int argv_size = 2;
	int argc = 0, total_length = 0;
	char **argv = malloc(argv_size * sizeof(char *));

	// Get system function index
	cmd = strtok_r(file_name, " ", &save_ptr);

	// Get args
	while(cmd != NULL) {
		total_length += strlen(cmd) + 1;

		// Allocate stack frame
		*esp -= strlen(cmd) + 1;
		argv[argc] = *esp;
		argc++;


		//if(argc >= 64)
		//{
		//	free(argv);
		//	return false;
		//}

		// Resize argv if exceeded
		if (argc >= argv_size)
		{
			argv_size *= 2;
			argv = realloc(argv, argv_size * sizeof(char*));
		}

		// Push to args to stack
		memcpy(*esp, cmd, strlen(cmd) + 1);

		// Get next args
		cmd = strtok_r(NULL, " ", &save_ptr);
	}

	// Align word size to 4
	*esp = *esp - 4 + total_length % 4;

	// Set the last element
	argv[argc] = 0;

	// Push address of syscall index and args to stack in reverse order
	for(int i = argc; i >= 0; i--) {
		// Make space on stack
		*esp -= sizeof(char*);

		// Push data on stack
		memcpy(*esp, &argv[i], sizeof(char*));
	}

	// Push argv address
	cmd = *esp;
	*esp -= sizeof(char**);
	memcpy(*esp, &cmd, sizeof(char**));

	// Push count of argv list
	*esp -= sizeof(int);
	memcpy(*esp, &argc, sizeof(int));

	// Push byte right after argv array as return address
	*esp -= sizeof(void *);
	memcpy(*esp, &argv[argc], sizeof(void*));

	// Free memory
	free(argv);*/

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
