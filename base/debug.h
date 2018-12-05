#ifndef __CONFIG_H__
#define __CONFIG_H__

//#define MEM_DEBUG 1
#define TUN_DEBUG 1
#define EVENT_DEBUG 1
#define SOCK_DEBUG 1

/*ARRAY DEF, copy from kernel*/
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:(-!!(e)); }))
#define __must_be_array(a) BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof((arr)[0]) + __must_be_array(arr))

#if (MEM_DEBUG)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline void dbg_free(void *p, const char *file, int line)
{
    char buff[256];
    sprintf(buff, "%p.mem", p);
    if (unlink(buff) < 0)
    {
        printf("Double free: %p File: %s Line: %d\n", p, file, line);
    }
    free(p);
}

static inline void *dbg_malloc(size_t size, const char *file, int line)
{
    void *p = malloc(size);
    if (p == NULL)
    {
        return NULL;
    }
    char buff[256];
    sprintf(buff, "%p.mem", p);
    FILE *f = fopen(buff, "w");
    fprintf(f, "File: %s\nLine: %d\nSize: %zu bytes\n", file, line, size);
    fclose(f);
    return p;
}

static inline void *dbg_calloc(size_t count, size_t size, const char *file, int line)
{
    void *p = calloc(count, size);
    if (p == NULL)
    {
        return NULL;
    }
    char buff[256];
    sprintf(buff, "%p.mem", p);
    FILE *f = fopen(buff, "w");
    fprintf(f, "File: %s\nLine: %d\nSize: %zu bytes\n", file, line, count * size);
    fclose(f);
    return p;
}

static inline char *dbg_strdup(const char *s, const char *file, int line)
{
    size_t len = strlen(s);
    char *p = dbg_malloc(len + 1, file, line);
    return strcpy(p, s);
}

#define mem_free(x)      dbg_free(x, __FILE__, __LINE__)
#define mem_malloc(x)    dbg_malloc(x, __FILE__, __LINE__)
#define mem_calloc(x, y) dbg_calloc(x, y, __FILE__, __LINE__)
#define mem_strdup(x)    dbg_strdup(x, __FILE__, __LINE__)
#else
#define mem_free(x) free(x)
#define mem_malloc(x) malloc(x)
#define mem_calloc(x, y) calloc(x, y)
#define mem_strdup(x) strdup(x)
#endif

#include "log.h"

#if (TUN_DEBUG)
#define tun_inner_log inner_log
#else
#define tun_inner_log(...)
#endif

#if (EVENT_DEBUG)
#define ev_inner_log inner_log
#else
#define ev_inner_log(...)
#endif

#if (SOCK_DEBUG)
#define sock_inner_log inner_log
#else
#define sock_inner_log(...)
#endif

#endif
