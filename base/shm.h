#ifndef MMAP_ALLOCATOR_H
#define MMAP_ALLOCATOR_H

struct mmap_operator
{
    void *(*create  )(size_t size);
    void *(*alloc   )(void *map, size_t size);
    void *(*calloc  )(void *map, size_t size);
    void  (*free    )(void *map, void *ptr);
    void  (*dump    )(FILE *fp, void *map);
};
extern struct mmap_operator Mmap;
#endif
