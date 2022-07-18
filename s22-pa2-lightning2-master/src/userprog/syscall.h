#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "list.h"
struct fd_map
{
  int fd;
  struct file *mapped_file;
  struct list_elem elem;
};

void syscall_init (void);
void close(int fd);
void exit(int status);
#endif /* userprog/syscall.h */
