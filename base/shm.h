#ifndef MMAP_ALLOCATOR_H
#define MMAP_ALLOCATOR_H

#define MEM_MMAP    (1 << 0)
#define MEM_PRIV    (1 << 1)

struct mmap_operator
{
    void *(*create  )(int mem_type, size_t size);
    void  (*destroy )(void *map);
    void *(*alloc   )(void *map, size_t size);
    void *(*calloc  )(void *map, size_t size);
    void  (*free    )(void *map, void *ptr);
    void  (*dump    )(FILE *fp, void *map);
};
extern struct mmap_operator Mmap;
#endif
