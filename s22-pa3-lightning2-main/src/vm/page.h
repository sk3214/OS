#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <list.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "frame.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

/**
The type declaration for an entry to a process' page table.

Contains information important to being able to track and use pages. The
file struct (see type declaration) contains the file data that the process
stores within the page.

ofs is the pointer offset to the beginning this data (to be used to read with Pintos filesystem).
upage is the virtual address associated with this page.
read_bytes is the amount of bytes of data in this page that should be read if we fetch data from this page (size of the file)
zero_bytes is the amount of bytes within the page to zero if a zero-ed out page is requested.
bool writable indicates whether or not this page can have its contents overwritten.

The hash_elem should be used to maintain a hash table of these entries.
 */
struct 
page_table_entry
{
    uint8_t *user_page_addr;

    // File related info
    struct file *file;
    off_t offset;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;

    // To be put within a struct hash representing our table
    struct hash_elem page_elem;
};

struct page_table_entry *get_page_entry(uint8_t *addr);
struct page_table_entry *create_page(struct file *file, off_t ofs, uint8_t *upage,
                                                  uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool load_from_file(struct page_table_entry *pg_entry);
void remove_page_entry(struct page_table_entry *pg_entry);
bool expand_stack_memory(void *upage);
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED);
#endif /* vm/page.h */