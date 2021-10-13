#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define ARG_SIZE 3
#define FD_DEFAULT_SIZE 2

void syscall_init (void);
void syscall_exit(int status);

#endif /* userprog/syscall.h */
