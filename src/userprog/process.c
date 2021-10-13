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
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static void get_first_arg (const char *cmd_line, char *file_name);
static void get_args (const char *cmd_line, int *char_count, int *arg_count);
static bool push_args (const char *cmd_line, void **esp);
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static struct exit_status * init_exit_status(tid_t tid);

static void
get_first_arg (const char *cmd_line, char *file_name)
{
 const char *start = cmd_line;
 const char *end = 0;

 while(*start == ' ')
   start++;
 for (end = start; *end != '\0' && *end != ' '; end++)
   continue;
 strlcpy(file_name, cmd_line, end - start + 1);
}

static void
get_args (const char *cmd_line, int *char_count, int *arg_count)
{
    const char *cursor = cmd_line;

    while(*cursor != '\0')
    {
      while(*cursor == ' ')
        cursor++;
      if (*cursor == '\0')
        break;
      else
      {
        (*arg_count)++;
        while(*cursor != ' ' && *cursor != '\0')
        {
          (*char_count)++;
          cursor++;
        }
        if (*cursor == '\0')
          break;
      }
      cursor++;
    }
}

/* Pushes arguments and pointers onto the stack */
static bool
push_args (const char *cmd_line, void **esp)
{
  if (cmd_line == NULL)
    return false;

  /* Gets the number of args in cmd_line and the total number of characters
     which are neither a space nor \0 */
  int char_count = 0;
  int arg_count = 0;
  get_args(cmd_line, &char_count, &arg_count);

  /* Sets the amount of memory to allocate to be total number of characters
    which we just retrieved plus each words null terminator. We round up the
    number of bytes to the nearest word size to allow accesses to be word
    aligned and therefore faster */
  int arg_data_mem_size = char_count + arg_count;
  arg_data_mem_size = ROUND_UP(arg_data_mem_size, sizeof(int));

  /* Decrements esp by data size */
  *esp -= arg_data_mem_size;
  char *arg_data = (char *) (*esp);

  /* Decrements esp by number of args * pointer size  + 1 to include the null
    pointer*/
  *esp -= (arg_count + 1) * sizeof(char *);
  char **arg_ptr = (char **) (*esp);

  /* Checks to see if stack is gonna be too big */
  //TODO explain what each sizeof signifies
  int stack_size = arg_data_mem_size + (arg_count + 1) * sizeof(char *)
    + sizeof(char **) + sizeof(int) + sizeof(void *);
  if (stack_size > PGSIZE)
    return false;

  /* Loops through each args and copies it at arg_data then advances arg_data
     by the size of the arg */
  char *token, *save_ptr;
  int token_length;
  for (token = strtok_r ((char *) cmd_line, " ", &save_ptr); token != NULL;
    token = strtok_r (NULL, " ", &save_ptr))
  {
    token_length = strlen(token) + 1;
    strlcpy(arg_data, token, token_length);
    *arg_ptr = arg_data;

    arg_data += token_length;
    arg_ptr++;
  }

  /* Decrements esp and adds pointer to first element */
  *esp -= sizeof(char **);
  **((int **) esp) = (int) *esp + DWORD;

  /* Decrements esp and adds number of args */
  *esp -= sizeof(int);
  **((int **) esp) = (int) arg_count;

  /* Decrements esp and adds return address */
  *esp -= sizeof(void *);
  **((int **) esp) = 0;

  return true;
}

/* Starts a new thread running a user program loaded from
   CMD_LINE.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

 /* Gets the file_name from cmd_line and copies it into a new string buffer */
tid_t
process_execute (const char *cmd_line)
{
  char *cl_copy;
  tid_t tid;

  /* Make a copy of CMD_LINE.
     Otherwise there's a race between the caller and load(). */
  cl_copy = palloc_get_page (0);
  if (cl_copy == NULL)
    return TID_ERROR;
  strlcpy (cl_copy, cmd_line, PGSIZE);

  char file_name[MAX_FILE_NAME_SIZE];
  get_first_arg(cl_copy, file_name);

  /* Creates process struct to store relevant data */
  struct process_data pdata;

  sema_init(&pdata.loaded, 0);
  pdata.cmd_line = cl_copy;
  pdata.parent = thread_current();
  pdata.load_success = false;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, &pdata);

  /* Sema down to continue to free memory once loaded/failed loading */
  sema_down(&pdata.loaded);

  if (tid == TID_ERROR)
    palloc_free_page (cl_copy);

  return pdata.load_success ? tid : TID_ERROR;
}

/* Allocates and initialises exit_status, setting its chi to 0
 reflecting the thread this exit_status belongs to is still running so any
 parent calling wait() on it will be blocked */
static struct exit_status
*init_exit_status(tid_t tid)
{
  struct exit_status *es = malloc(sizeof(struct exit_status));
  if (es == NULL)
    return NULL;
  es->has_terminated = false;
  es->tid = tid;
  return es;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct process_data *pdata = (struct process_data *) aux;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (pdata->cmd_line, &if_.eip, &if_.esp);

  /* Push arguments on stack */
  success = success && push_args (pdata->cmd_line, &if_.esp);

  pdata->load_success = success;

  if (success)
  {
    /* Get file name writing to executable */
    char file_name[MAX_FILE_NAME_SIZE];
    get_first_arg(pdata->cmd_line, file_name);

    /* Gets parent thread and sets the pointer and is_kernel accordingly */
    struct thread *cur = thread_current();
    cur->is_kernel = false;
    cur->parent = pdata->parent;

    /* Deny writing to executable */
    struct file *f = filesys_open(file_name);
    if (f != NULL)
    {
      file_deny_write(f);
      cur->exec_file = f;
    }

    /* initialises exit_status struct and adds to parent chlid_status_list */
    struct exit_status *child_es = init_exit_status(cur->tid);
    if (child_es != NULL)
      list_push_back(&pdata->parent->child_status_list, &child_es->elem_status);
  }

  /* If load failed, quit. */
  palloc_free_page (pdata->cmd_line);

  /* Sema up to allow cmd_line to be freed */
  sema_up(&pdata->loaded);

  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
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
process_wait (tid_t child_tid UNUSED)
{
  struct thread *cur = thread_current();

  /* Searches through  child_status_list for exit_status struct which matches
     child_tid */
  lock_acquire(&cur->child_status_lock);

  struct list_elem *e;
  for(e = list_begin(&cur->child_status_list);
      e != list_end(&cur->child_status_list); e = list_next(e))
  {
      struct exit_status *child_es = list_entry(e, struct exit_status,
              elem_status);

      if(child_es->tid == child_tid)
      {

        /* Waits on condition until child process has terminated */
        while(!child_es->has_terminated)
          cond_wait(&cur->child_status_cond, &cur->child_status_lock);

        /* Frees exit_status struct for the child that terminated */
        int exit_code = child_es->exit_code;

        list_remove(e);
        free(child_es);
        lock_release(&cur->child_status_lock);
        return exit_code;
      }
  }
  lock_release(&cur->child_status_lock);
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  if (!cur->is_kernel)
    printf("%s: exit(%i)\n", cur->name, cur->exit_code);

  /* Frees exit_status for each child */
  lock_acquire(&cur->child_status_lock);

  struct list_elem *next;
  for(struct list_elem *e = list_begin(&cur->child_status_list);
    e != list_end(&cur->child_status_list);)
  {
    next = list_next(e);

    struct exit_status *child_es = list_entry(e, struct exit_status,
      elem_status);
    list_remove(e);

    free(child_es);

    e = next;
  }

  lock_release(&cur->child_status_lock);

  /* Close any opened files and free fd_arr */
  if (cur->fd_count > 0)
  {
    for(int i = 0; i < cur->fd_size; i++)
    {
      if (cur->fd_arr[i] != NULL)
      {
        struct file *f = cur->fd_arr[i];
        file_close(f);
      }
    }
    free(cur->fd_arr);
  }

  /* Make sure we close and re-enable write access to executable */
  if (cur->exec_file != NULL)
  {
    file_allow_write(cur->exec_file);
    file_close(cur->exec_file);
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

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmd_line, void (**eip) (void), void **esp)
{
  char file_name[MAX_FILE_NAME_SIZE];
  get_first_arg(cmd_line, file_name);

  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

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

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
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

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
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
