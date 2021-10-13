#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include <string.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static uint32_t get_arg (int *esp, int offset);

static void syscall_handler (struct intr_frame *);

/* Lock for thread safe handling of files */
static struct lock filesys_lock; // TODO: put this back in

static void _halt (struct intr_frame *);
static void _exit (struct intr_frame *);
static void _exec (struct intr_frame *);
static void _wait (struct intr_frame *);
static void _create (struct intr_frame *);
static void _remove (struct intr_frame *);
static void _open (struct intr_frame *);
static void _filesize (struct intr_frame *);
static void _read (struct intr_frame *);
static void _write (struct intr_frame *);
static void _seek (struct intr_frame *);
static void _tell (struct intr_frame *);
static void _close (struct intr_frame *);

/* Array storing function pointers to the individual functions handling the
   system calls. The function pointers are ordered such that the index of each
   system call's function matches its respective system call enum index so
   that the enum index of each system call can be mapped to its respective
   function. */
static void (*syscall_arr[]) (struct intr_frame *);

static void (*syscall_arr[]) (struct intr_frame *) =
{
  _halt,
  _exit,
  _exec,
  _wait,
  _create,
  _remove,
  _open,
  _filesize,
  _read,
  _write,
  _seek,
  _tell,
  _close
};

/* Checks if the virtual address is not null and maps to a legitimate memory
   location by querying pagedir_get_page() */
static bool is_page_mem_valid(const void *vaddr);

/* Checks if the virtual address is not null and if the address is below
   PHYS_BASE by querying is_user_vaddr() */
static bool is_vaddr_range_valid(const void *start, unsigned length);

/* Checks if the file descriptor is either STDIN or STDOUT. If not we index the
   file descriptor in the dynamic array and check if it maps to a file struct */
static bool is_fd_valid(struct thread *t, int fd);
static struct file *fd_arr_get(struct thread *t, int fd);
static int fd_arr_add(struct thread *t, struct file *f);
static int fd_arr_remove(struct thread *t, int fd);

static uint32_t
get_arg (int *esp, int offset)
{
  if (!is_user_vaddr(esp + offset))
    syscall_exit(-1);

  return (uint32_t) *(esp + offset);
}

void
syscall_init (void)
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int *esp = f->esp;
  if (!is_vaddr_range_valid(esp, 0) || !is_page_mem_valid(esp))
    syscall_exit(-1);

  syscall_arr[(int) *esp](f);
}

void
syscall_exit (int status)
{
    struct thread *child = thread_current();
    struct thread *parent = child->parent;

    /* if exiting process has no parent don't need to save its state or
    signal parent */
    child->exit_code = status;

    /* if exiting process has a parent must update its exit_status struct so
      parent can see it has terminated and signals it parent to wake up if
      waiting on it. */
    if (parent != NULL)
    {
        /* Need to lock here in case exit_status has been freed when parent is
           try to exit at the same time as a child */
        lock_acquire(&parent->child_status_lock);

        struct list_elem *e;
        for (e = list_begin(&parent->child_status_list);
             e != list_end(&parent->child_status_list); e = list_next(e))
        {
          struct exit_status *child_es = list_entry(e, struct exit_status,
              elem_status);
          if (child_es->tid == child->tid)
          {
              child_es->exit_code = status;
              child_es->has_terminated = true;
              cond_signal(&parent->child_status_cond,
                &parent->child_status_lock);
              break;
          }
        }

        lock_release(&parent->child_status_lock);
    }
    thread_exit();
}


static void
_halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}


static void
_exit (struct intr_frame *f UNUSED)
{
  int status = get_arg(f->esp, 1);
  syscall_exit(status);
}

static void
_exec (struct intr_frame *f UNUSED)
{
  const char *cmd_line = (char *) get_arg(f->esp, 1);

  /* Checks if memory we are reading from is valid */
  if (!is_vaddr_range_valid(cmd_line, 0))
    syscall_exit(-1);

  if (!is_page_mem_valid(cmd_line))
    syscall_exit(-1);

  if (!is_vaddr_range_valid(cmd_line, strlen(cmd_line)))
    syscall_exit(-1);

  f->eax = (pid_t) process_execute(cmd_line);
}

static void
_wait (struct intr_frame *f UNUSED)
{
  pid_t pid = get_arg(f->esp, 1);
  f->eax = (uint32_t) process_wait(pid);
}

static void
_create (struct intr_frame *f UNUSED)
{
  const char *file_name = (const char *) get_arg(f->esp, 1);
  unsigned size = (unsigned) get_arg(f->esp, 2);

  /* Checks if memory we are reading from is valid */
  if (!is_vaddr_range_valid(file_name, 0))
    syscall_exit(-1);

  if (!is_page_mem_valid(file_name))
    syscall_exit(-1);

  if (!is_vaddr_range_valid(file_name, strlen(file_name)))
    syscall_exit(-1);

  lock_acquire(&filesys_lock);
  bool success = filesys_create(file_name, size);
  lock_release(&filesys_lock);

  f->eax = (uint32_t) success;
}

static void
_remove (struct intr_frame *f UNUSED)
{
  const char *file_name = (const char *) get_arg(f->esp, 1);

  /* Checks if memory we are reading from is valid */
  if (!is_vaddr_range_valid(file_name, 0))
    syscall_exit(-1);

  if (!is_page_mem_valid(file_name))
    syscall_exit(-1);

  if (!is_vaddr_range_valid(file_name, strlen(file_name)))
    syscall_exit(-1);

  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file_name);
  lock_release(&filesys_lock);

  f->eax = (uint32_t) success;
}

static void
_open (struct intr_frame *f UNUSED)
{
  const char *file_name = (const char *) get_arg(f->esp, 1);

  /* Checks if memory we are reading from is valid */
  if (!is_vaddr_range_valid(file_name, 0))
    syscall_exit(-1);

  if (!is_page_mem_valid(file_name))
    syscall_exit(-1);

  if (!is_vaddr_range_valid(file_name, strlen(file_name)))
    syscall_exit(-1);

  struct thread *cur = thread_current();

  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(file_name);
  lock_release(&filesys_lock);

  if (file == NULL)
  {
      f->eax = (uint32_t) -1;
      return;
  }

  /* Adds file to list of files indexed by their file descriptors */
  int fd = fd_arr_add(cur, file);
  f->eax = (uint32_t) fd;

}

static void
_filesize (struct intr_frame *f UNUSED)
{
  int fd = (int) get_arg(f->esp, 1);

  struct thread *cur = thread_current();

  /* Checks if file descriptor is valid */
  if (!is_fd_valid(cur, fd))
    syscall_exit(-1);

  struct file *file = fd_arr_get(cur, fd);
  if (file == NULL)
    syscall_exit(-1);

  lock_acquire(&filesys_lock);
  int size = (int) file_length(file);
  lock_release(&filesys_lock);


  f->eax = (uint32_t) size;

}

static void
_read (struct intr_frame *f UNUSED)
{
  int fd = (int) get_arg(f->esp, 1);
  const void *buffer = (const void *) get_arg(f->esp, 2);
  unsigned size = (unsigned) get_arg(f->esp, 3);

  struct thread *cur = thread_current();

  /* Checks if memory we are reading from is valid */
  if (!is_vaddr_range_valid(buffer, size))
    syscall_exit(-1);

  /* Checks if file descriptor is valid */
  if (!is_fd_valid(cur, fd))
    syscall_exit(-1);

  /* Checks if fd = 0 i.e. in reading mode */
  if (fd == STDOUT_FILENO)
    syscall_exit(-1);

  if (fd == STDIN_FILENO)
  {
    for (int i = 0; i < (int) size; i++)
    {
      ((char *) buffer)[i] = input_getc();
    }
    f->eax = size;
  }
  else
  {
    struct file *file = fd_arr_get(cur, fd);
    if (file == NULL)
      syscall_exit(-1);

    lock_acquire(&filesys_lock);
    int byte_size = file_read(file, (void *) buffer, size);
    lock_release(&filesys_lock);

    f->eax = (uint32_t) byte_size;
  }
}

static void
_write (struct intr_frame *f UNUSED)
{
  int fd = (int) get_arg(f->esp, 1);
  const void *buffer = (const void *) get_arg(f->esp, 2);
  unsigned size = (unsigned) get_arg(f->esp, 3);

  struct thread *cur = thread_current();

  /* Checks if memory we are reading from is valid */
  if (!is_vaddr_range_valid(buffer, size))
    syscall_exit(-1);

  if (!is_page_mem_valid(buffer))
    syscall_exit(-1);

  /* Checks if file descriptor is valid */
  if (!is_fd_valid(cur, fd))
    syscall_exit(-1);

  /* Checks if fd = 1 i.e. in writing mode */
  if (fd == STDIN_FILENO)
    syscall_exit(-1);

  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    f->eax = size;
  }
  else
  {
    struct file *file = fd_arr_get(cur, fd);
    if (file == NULL)
      syscall_exit(-1);

    lock_acquire(&filesys_lock);
    int byte_size = file_write(file, buffer, size);
    lock_release(&filesys_lock);

    f->eax = (uint32_t) byte_size;
  }
}

static void
_seek (struct intr_frame *f UNUSED)
{
  int fd = (int) get_arg(f->esp, 1);
  unsigned position = (unsigned) get_arg(f->esp, 2);

  struct thread *cur = thread_current();

  /* Checks if file descriptor is valid */
  if (!is_fd_valid(cur, fd))
    syscall_exit(-1);

  struct file *file = fd_arr_get(cur, fd);
  if (file == NULL)
    syscall_exit(-1);

  file_seek(file, position);

}

static void
_tell (struct intr_frame *f UNUSED)
{
  int fd = (int) get_arg(f->esp, 1);

  struct thread *cur = thread_current();

  /* Checks if file descriptor is valid */
  if (!is_fd_valid(cur, fd))
    syscall_exit(-1);

  struct file *file = fd_arr_get(cur, fd);
  if (file == NULL)
    syscall_exit(-1);

  f->eax = (unsigned) file_tell(file);
}

static void
_close (struct intr_frame *f UNUSED)
{
  int fd = (int) get_arg(f->esp, 1);

  struct thread *cur = thread_current();

  /* Check if either of stdio file descriptors */
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return;

  /* Checks if file descriptor is valid */
  if (!is_fd_valid(cur, fd))
    syscall_exit(-1);

  struct file *file = fd_arr_get(cur, fd);
  if (file == NULL)
    syscall_exit(-1);

  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);

  fd_arr_remove(cur, fd);
}

static bool
is_page_mem_valid(const void *vaddr)
{
  if (vaddr == NULL)
    return false;
  uint32_t *page_ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (page_ptr == NULL || *page_ptr == 0)
    return false;

  return true;
}

static bool
is_vaddr_range_valid(const void *start, unsigned length)
{
  if (start == NULL)
    return false;
  if (!is_user_vaddr(start) || !is_user_vaddr(start + length))
    return false;
  return true;
}

static bool
is_fd_valid(struct thread *t, int fd)
{
  if (fd < 0)
    return false;
  if (fd == STDOUT_FILENO || fd == STDIN_FILENO)
    return true;

  int raw_fd = fd - FD_DEFAULT_SIZE;
  if (raw_fd >= t->fd_size)
    return false;

  return t->fd_arr[raw_fd] != NULL;

}

static struct file
*fd_arr_get(struct thread *t, int fd)
{
  return t->fd_arr[fd - FD_DEFAULT_SIZE];
}

/* fd_arr is increased in size by using realloc for each new file that is
   opened. This increases fd_count and fd_size. If a file is closed, the
   pointer for that file descriptor is set to NULL such that it can be reused.
   This decrements the fd_count but keeps fd_size the same.*/
static int
fd_arr_add(struct thread *t, struct file *f)
{
  if (t->fd_count < t->fd_size)
  {
    for (int i = 0; i < t->fd_size; i++)
    {
      if (t->fd_arr[i] == NULL)
      {
        t->fd_arr[i] = f;
        t->fd_count++;

        return i + FD_DEFAULT_SIZE;
      }
    }
    return -1;
  }
  else
  {
    int i = t->fd_count;

    t->fd_count++;
    t->fd_arr = (struct file **) realloc(t->fd_arr,
      t->fd_count * sizeof(struct file *));
    t->fd_arr[i] = f;

    t->fd_size++;

    return i + FD_DEFAULT_SIZE;
  }
}

static int
fd_arr_remove(struct thread *t, int fd)
{
  if (!is_fd_valid(t, fd))
    return -1;

  t->fd_arr[fd - FD_DEFAULT_SIZE] = NULL;
  t->fd_count--;

  return 0;
}
