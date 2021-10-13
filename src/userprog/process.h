#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

#define MAX_FILE_NAME_SIZE 14   /* The maximum number of characters for the
                                   file_name. */
#define DWORD 4

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process_data {
  struct semaphore loaded;      /* Semaphore to indicate load completion. */
  char *cmd_line;               /* Stores filename and arguments. */
  struct thread *parent;        /* Stores pointer to parent thread. */
  bool load_success;            /* Indicates whether load was successful. */
};

#endif /* userprog/process.h */
