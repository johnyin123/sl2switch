#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "shm.h"

typedef struct data_t
{
    void *data;
    size_t data_size;
    struct data_t *next;
} data_t;

typedef struct mem_t
{
    struct data_t *data;
    void *end_ptr;
    struct mem_t *next;
} mem_t;


static void *alloc_mmap_start(mem_t *mem, size_t size)
{
    data_t new_node;
    new_node.data = (void *)mem + sizeof(mem_t) + sizeof(data_t);
    new_node.data_size = size;
    new_node.next = NULL;
    mem->data = (void *)mem + sizeof(mem_t);
    memcpy((void *)mem + sizeof(mem_t), &new_node, sizeof(data_t));
    return (new_node.data);
}

static data_t *get_last_node(void *map)
{
    data_t *tmp = ((mem_t *) map)->data;
    while (tmp->next != NULL)
        tmp = tmp->next;
    return (tmp);
}

static size_t get_mmap_total_size(void *map)
{
    size_t total_size = sizeof(mem_t);
    data_t *tmp = ((mem_t *) map)->data;
    while (tmp != NULL)
    {
        total_size += sizeof(data_t) + tmp->data_size;
        tmp = tmp->next;
    }
    return (total_size);
}

static void *alloc_new_node(void *map, size_t size)
{
    int count;
    data_t new_node;
    count = get_mmap_total_size(map);
    new_node.data_size = size;
    new_node.data = map + count + sizeof(data_t);
    new_node.next = NULL;
    memcpy(map + count, &new_node, sizeof(data_t));
    get_last_node(map)->next = map + count;
    return (new_node.data);
}

static data_t *find_free_node(data_t *data, size_t size)
{
    data_t *tmp = data;
    while (tmp != NULL)
    {
        if (tmp->data == NULL && tmp->data_size >= size)
            return (tmp);
        tmp = tmp->next;
    }
    return (NULL);
}

static void *get_next_alloc_space(void *map, size_t size)
{
    data_t *tmp;
    data_t new_node;
    if ((tmp = find_free_node(((mem_t *) map)->data, size)) == NULL)
        return (alloc_new_node(map, size));
    if (tmp->data_size >= size + sizeof(data_t))
    {
        new_node.data_size = tmp->data_size - size - sizeof(data_t);
        new_node.data = NULL;
        new_node.next = tmp->next;
        tmp->data_size = size;
        tmp->next = (void *)tmp + size + sizeof(data_t);
        memcpy((void *)tmp + size + sizeof(data_t), &new_node, sizeof(data_t));
    }
    tmp->data = (void *)tmp + sizeof(data_t);
    return (tmp->data);
}

static size_t get_new_mmap_size(data_t *data)
{
    size_t size = data->data_size;
    data = data->next;
    while (data != NULL && data->data == NULL)
    {
        size += sizeof(data_t) + data->data_size;
        data = data->next;
    }
    return (size);
}

static void *get_new_next_ptr(data_t *data)
{
    data = data->next;
    while (data != NULL)
    {
        if (data->data != NULL)
            return (data);
        data = data->next;
    }
    return (NULL);
}

static void *get_mmap_data_from_ptr(void *map, void *ptr)
{
    mem_t *mem = (mem_t *) map;
    data_t *tmp;
    for (tmp = mem->data; tmp != NULL; tmp = tmp->next)
        if (tmp->data == ptr)
            return (tmp);
    return (NULL);
}

static void *mmap_create(size_t size)
{
    int protection = PROT_READ | PROT_WRITE;
    int visibility = MAP_ANONYMOUS | MAP_SHARED;
    void *shmem = mmap(NULL, size, protection, visibility, -1, 0);
    mem_t mem = { NULL, shmem + size, NULL };
    memcpy(shmem, &mem, sizeof(mem_t));
    return (shmem);
}

static void *get_allocable_page(void *map, size_t page_size, size_t size)
{
    mem_t *mem = (mem_t *) map;
    mem_t *tmp = mem;
    data_t *node = NULL;
    while (tmp != NULL)
    {
        if (tmp->data == NULL || (node = find_free_node(tmp->data, size)) != NULL)
            return (tmp);
        else if ((void *)tmp + get_mmap_total_size(tmp) + sizeof(data_t) + size <= tmp->end_ptr)
            return (tmp);
        mem = tmp;
        tmp = tmp->next;
    }
    tmp = mmap_create((page_size >= sizeof(mem_t) + sizeof(data_t) + size) ? page_size : sizeof(mem_t) + sizeof(data_t) + size);
    mem->next = (void *)tmp;
    return (tmp);
}

static void remap_mmap_free(void *map)
{
    mem_t *mem = (mem_t *) map;
    data_t *tmp;
    for (tmp = mem->data; tmp != NULL; tmp = tmp->next)
    {
        if (tmp->data == NULL)
        {
            tmp->data_size = get_new_mmap_size(tmp);
            tmp->next = get_new_next_ptr(tmp);
        }
    }
}


static void *mmap_alloc(void *map, size_t size)
{
    void *mem;
    data_t *tmp;
    size_t page_size = (size_t) getpagesize();
    mem = get_allocable_page(map, page_size, size);
    tmp = ((mem_t *) mem)->data;
    if (mem == NULL)
        return (NULL);
    if (tmp == NULL)
        return (alloc_mmap_start(mem, size));
    return (get_next_alloc_space(mem, size));
}

static void *mmap_calloc(void *map, size_t size)
{
    void *ptr = mmap_alloc(map, size);
    if (ptr == NULL)
        return (NULL);
    memset(ptr, 0, size);
    return (ptr);
}

static void mmap_free(void *map, void *ptr)
{
    mem_t *mem = (mem_t *) map;
    data_t *data = NULL;
    while (mem != NULL)
    {
        if ((data = get_mmap_data_from_ptr((void *)mem, ptr)) != NULL)
            break;
        mem = mem->next;
    }
    if (data == NULL)
        return;
    data->data = NULL;
    remap_mmap_free((void *)mem);
}

static void dump_mem_info(FILE *fp, void *map)
{
    mem_t *mem = (mem_t *) map;
    data_t *tmp;
    while (mem != NULL)
    {
        tmp = mem->data;
        while (tmp != NULL)
        {
            fprintf(fp, "page %p, node %p, size %Zu, data %p, next %p\n", mem, tmp, tmp->data_size, tmp->data, mem->next);
            tmp = tmp->next;
        }
        mem = mem->next;
    }
}

struct mmap_operator Mmap =
{
    .create = mmap_create,
    .alloc  = mmap_alloc,
    .calloc = mmap_calloc, 
    .free   = mmap_free, 
    .dump   = dump_mem_info, 
};

