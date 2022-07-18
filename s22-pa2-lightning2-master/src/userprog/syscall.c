#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "process.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"

struct lock read_write_lock;

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  lock_init(&read_write_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&read_write_lock);
}

int write(int fd, const void *buf, unsigned size);
int wait(tid_t pid);
tid_t exec( const char * cmd);
void halt(void);
void validate_address(const void* addr);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
void close(int fd);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
void seek(int fd,unsigned position);
unsigned tell(int fd);

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // printf ("system call!\n");
  void *stack_pointer = f->esp;
  // f->eax;
  validate_address((const void *)stack_pointer);
  int *syscall_num = (int*) stack_pointer;
  
  validate_address((const void *)(int *)(stack_pointer)+4);
  switch (*syscall_num)
  {
  case SYS_EXIT:
  {
    exit(*(int *)(stack_pointer + 4));
    break;
  }

  case SYS_WRITE:
  {
    validate_address((const void*)*(int*)(stack_pointer + 8));
    f->eax = write(*(int *)(stack_pointer + 4),
          (const void *)*(int *)(stack_pointer + 8), *(int *)(stack_pointer + 12));
    // write();
    break;
  }
  case SYS_CREATE:
  {
    // Safe memory access
    validate_address((const void*)*(int*)(stack_pointer + 4));
    f->eax = create((const char *)*(int *)(stack_pointer + 4), (unsigned)*(int *)(stack_pointer + 8));
    break;
  }

  case SYS_REMOVE:
  {
    // Safe memory access
    f->eax = remove((const char *)*(int *)(stack_pointer + 4));
    break;
  }

  case SYS_OPEN:
  {
    // Safe memory access
    validate_address((const void*)*(int*)(stack_pointer + 4));
    f->eax = open((const char *)*(int *)(stack_pointer + 4));
    break;
  }
  case SYS_WAIT: {
    // hex_dump( (uintptr_t) stack_pointer, stack_pointer, PHYS_BASE-stack_pointer, true);
    f->eax = wait(*(int *)(stack_pointer + 4));
    break;
  }
  case SYS_EXEC: {
    // hex_dump( (uintptr_t) stack_pointer, stack_pointer, PHYS_BASE-stack_pointer, true);
    validate_address((const void*)*(int*)(stack_pointer + 4));
    f->eax = exec((const char *)*(int *)(stack_pointer + 4));
    break;
  }
  case SYS_HALT: {
    halt();
    break;
  }
  case SYS_CLOSE:
  {
    // Safe memory access
    close(*(int *)(stack_pointer + 4));
    break;
  }

  case SYS_FILESIZE:
  {
    // Safe memory access
    f->eax = filesize(*(int *)(stack_pointer + 4));
    break;
  }
  case SYS_READ:
  {
    // Safe memory access
    validate_address((const void*)*(int*)(stack_pointer + 8));
    f->eax = read(*(int *)(stack_pointer + 4), (void *)*(int *)(stack_pointer + 8), *(int *)(stack_pointer + 12));
    break;
  }
  case SYS_SEEK: {
    seek(*(int *)(stack_pointer + 4),*(int *)(stack_pointer + 8));
    break;
  }
  case SYS_TELL: {
    validate_address((const void*)*(int*)(stack_pointer + 4));
    f->eax = tell(*(int *)(stack_pointer + 4));
    break;
  }
  default:
    break;
  }
  // thread_exit ();
}

void validate_address(const void *addr)
{
  // printf("Thread name: %s\n",thread_current()->name);
  // printf("Addr %d\n",*(int *)addr);
  if (!is_user_vaddr(addr))
  {
    // printf("User\n");
    exit(-1);
  }
  if ((void *)pagedir_get_page(thread_current()->pagedir, addr) == NULL)
  {
    // printf("Thread name: %s\n",thread_current()->name);
    exit(-1);
  }
  if(is_kernel_vaddr(addr)){
    exit(-1);
  }
}

void exit(int status){
  char * tokenized_name,*save_ptr;
  char *name = malloc(strlen(thread_current()->name)+1);
  strlcpy(name,thread_current()->name,strlen(thread_current()->name)+1);
  tokenized_name = strtok_r(name," ",&save_ptr);
  printf("%s: exit(%d)\n",tokenized_name, status);
  thread_current()->exit_status = status;
  thread_exit();
}

int write(int fd, const void *data, unsigned size)
{
  // printf("Inside write\n and fd is %d\n",fd);
  // puts(data);
  if (fd == STDOUT_FILENO)
  {
    // printf("Did I come here ? \n");
    putbuf(data, size);
    return size;
  }
  else {
    struct list_elem *e;
    struct file *write_file = NULL;
    for (e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e))
    {
      if (((struct fd_map *)list_entry(e, struct fd_map, elem))->fd == fd)
      {
        write_file = ((struct fd_map *)list_entry(e, struct fd_map, elem))->mapped_file;
      }
    }
    if(write_file == NULL)
      return 0;
    lock_acquire(&read_write_lock);
    int w_size = file_write(write_file,data,size);
    lock_release(&read_write_lock);
    return w_size;
  }
  return 0;
}

int wait(tid_t pid) {
  // printf("Started %d\n",pid);
  // return 0;
  return process_wait(pid);
}

int exec( const char * cmd) {
  // printf("%s\n",(char *)cmd);
  int pid = process_execute(cmd);
  struct thread *t = get_thread_with_pid(pid);
  sema_down(&t->wait_load);
  if(t->load_failed)
    return -1;
  // printf("PID in exec: %d\n",pid);
  return pid;
}

void halt() {
  shutdown_power_off();
}

bool create(const char *file, unsigned initial_size)
{
  if(file == NULL){
    return false;
  }
  return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
  bool ret = false;
  lock_acquire(&read_write_lock);
  // printf("Deleting\n");
  ret = filesys_remove(file);
  // printf("Deleted\n bool: %d\n",ret);
  lock_release(&read_write_lock);
  return ret;
}

int open(const char *file)
{
  if (file == NULL)
  {
    return -1;
  }
  struct file *opened_file = filesys_open(file);
  if (opened_file != NULL)
  {
    struct fd_map *file_fd = malloc(sizeof(struct fd_map));
    if (file_fd != NULL)
    {
      file_fd->mapped_file = opened_file;
      if (!list_empty(&thread_current()->fd_list))
      {
        // file_fd->fd = 1;
        file_fd->fd = ((struct fd_map *)list_entry(list_back(&thread_current()->fd_list), struct fd_map, elem))->fd + 1;
        // printf("FD Val: %d", file_fd->fd);
      }
      else
      {
        file_fd->fd = 2;
        // printf("List Empty: %d", file_fd->fd);
      }
      list_push_back(&thread_current()->fd_list, &file_fd->elem);
      return file_fd->fd;
    }
    return -1;
  }
  else
  {
    return -1;
  }
}

void close(int fd)
{
  if (fd >= 2 && !list_empty(&thread_current()->fd_list))
  {
    struct list_elem *e;
    for (e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e))
    {
      if (((struct fd_map *)list_entry(e, struct fd_map, elem))->fd == fd)
      {
        file_close(((struct fd_map *)list_entry(e, struct fd_map, elem))->mapped_file);
        list_remove(e);
      }
    }
  }
}

int filesize(int fd)
{
  struct file *s_file;
  if (fd >= 2 && !list_empty(&thread_current()->fd_list))
  {
    struct list_elem *e;
    for (e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e))
    {
      if (((struct fd_map *)list_entry(e, struct fd_map, elem))->fd == fd)
      {
        s_file = ((struct fd_map *)list_entry(e, struct fd_map, elem))->mapped_file;
        return file_length(s_file);
      }
    }
  }
  return 0;
}

int read(int fd, void *buffer, unsigned size)
{
  // printf("\nReading fd: %d\n", fd);
  if (fd < 0)
  {
    return -1;
  }
  if (fd == STDIN_FILENO)
  {
    // Do Something
    unsigned i;
    int bytes_counted = size;
    int *new_buffer = (int *)buffer;
    for (i = 0; i < size; i++)
    {
      new_buffer[i] += input_getc();
    }
    return bytes_counted;
  }
  else
  {
    // printf("\nReading fd: %d\n", fd);
    struct file *s_file;
    if (!list_empty(&thread_current()->fd_list))
    {
      struct list_elem *e;
      for (e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e))
      {
        if (((struct fd_map *)list_entry(e, struct fd_map, elem))->fd == fd)
        {
          int bytes_counted = 0;
          // printf("\nFound file\n");
          s_file = ((struct fd_map *)list_entry(e, struct fd_map, elem))->mapped_file;
          // printf("\nExecuting file_read\n");
          lock_acquire(&read_write_lock);
          bytes_counted = file_read(s_file, buffer, size);
          lock_release(&read_write_lock);
          return bytes_counted;
        }
      }
    }
  }
  return -1;
}
void seek(int fd,unsigned position){
  if (!list_empty(&thread_current()->fd_list))
  {
    struct list_elem *e;
    struct file *seek_file = NULL;
    for (e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e))
    {
      if (((struct fd_map *)list_entry(e, struct fd_map, elem))->fd == fd)
      {
          seek_file = ((struct fd_map *)list_entry(e, struct fd_map, elem))->mapped_file;
          lock_acquire(&read_write_lock);
          file_seek(seek_file,position);
          lock_release(&read_write_lock);
          break;
      }
    }
  }  
}

unsigned tell(int fd){
  if (!list_empty(&thread_current()->fd_list))
  {
    struct list_elem *e;
    struct file *tell_file = NULL;
    for (e = list_begin(&thread_current()->fd_list); e != list_end(&thread_current()->fd_list); e = list_next(e))
    {
      if (((struct fd_map *)list_entry(e, struct fd_map, elem))->fd == fd)
      {
        tell_file = ((struct fd_map *)list_entry(e, struct fd_map, elem))->mapped_file;
        lock_acquire(&read_write_lock);
        int tell_val = file_tell(tell_file);
        lock_release(&read_write_lock);
        return tell_val;
      }
    }
  }  
  return -1;
}
