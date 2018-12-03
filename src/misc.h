#ifndef __MISC__
#define __MISC__

#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

#define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
int getsock_ip(int fd, char *ipaddr, socklen_t len, ushort *port);
int settimeout(const int fd);
void setcloseexec(int fd);
int setreuseport(int fd);
int setreuseaddr(int fd);
int getsockerror(int fd);
bool valid_digit(const char *str);
bool is_valid_ip(const char *ip_str);
void dump_hex(FILE *fp, const void *vptr, int size, const char *fmt, ...);

#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include "debug.h"
static inline char *get_abs_path(char *p, size_t size)
{
    //char p[PATH_MAX];
    int cnt = readlink("/proc/self/exe", p, size);
    if (cnt < 0 || cnt >= size)
        return NULL;
    p[cnt] = '\0';
    return dirname(p);
}

static inline bool file_exist(const char *filepath)
{
    if (access(filepath, F_OK) == 0) return true;
    return false;
}

static inline off_t get_file_size(const char *filepath)
{
    struct stat finfo;
    if (stat(filepath, &finfo) < 0)
        return -1;
    return finfo.st_size;
}
/*  misc_util.c */
void script_init_env(const char *ifname, const char *nodename);
pid_t run_script(const char *script, bool wait);

/*  misc_pktdmp.c */
#define ether_dump(buf, size) _ether_dump(buf, size, "[%s(%s:%d)] ", __FUNCTION__, __FILE__, __LINE__)
void _ether_dump(void *buf, int size, const char *fmt, ...);

#endif
