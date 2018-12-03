#ifndef __TUN_DEV_H__
#define __TUN_DEV_H__
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>        // <-- This one
#include <linux/if.h>
#include <linux/if_tun.h>
#include "debug.h"

typedef struct tundev_t
{
    char devname[IFNAMSIZ];  /* tun/tap name */
    int tfd;        /* tun/tap device fd */
    uint64_t mac;   /* 0xFFFFFFFFFFFF0000 */
    void *ctx;
} tundev_t;

struct tun_operator
{
    int (*open) (tundev_t *tdev, const char *dev);
    int (*close) (tundev_t * tdev);
    int (*write) (tundev_t * tdev, char *buf, int len);
    int (*read) (tundev_t * tdev, char *buf, int len);
    void *(*get_ctx) (tundev_t * tdev);
    void (*set_ctx) (tundev_t * tdev, void *data);
    int (*getfd) (tundev_t * tdev);
    const char *(*getname) (tundev_t * tdev);
    uint64_t (*getmac) (tundev_t * tdev);
};

extern struct tun_operator Tun;
#endif
