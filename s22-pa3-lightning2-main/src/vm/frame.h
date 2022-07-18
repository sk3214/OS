#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include <hash.h>
#include "threads/palloc.h"
#include "page.h"

/**
The type declaration for an entry to the frame table (cache).
Keeps track of the thread that is currently using this frame (has a page
installed into it for the CPU to use in execution). It also keeps track
of the page that is contained within it and its (the frame table entry's)
own address.

The hash_elem should be used to maintain a hash table of these entries.
 */

struct frame_table_entry
{
    struct thread *holder;
    struct page_table_entry *mapped_page;
    void *frame_addr;

    // To be put within a struct hash representing our table
    struct hash_elem frame_elem;
};

void init_frame_table(void);
struct frame_table_entry *get_frame_entry(void *frame_ptr);
struct frame_table_entry *allocate_frame(struct page_table_entry *pg);
void remove_frame(struct frame_table_entry *frame);
unsigned
frame_hash (const struct hash_elem *p_, void *aux UNUSED);
bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED);
#endif /* vm/frame.h */
