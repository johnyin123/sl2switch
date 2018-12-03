#ifndef __CONF_H__
#define __CONF_H__

#include <stdint.h>
#include "peer.h"
#include "list.h"
#include "tun_dev.h"
#include "async_socket.h"

typedef struct outgoing_t
{
    uint32_t ipaddr;
    ushort port;
    list_t link;
} outgoing_t;

typedef struct conf_t
{
    outgoing_t outgoing;
    peer_t peers;
    ev_loop_t event_loop;
    connection_t srv;
    tundev_t tdev;
    ushort port;
    int maxfds;
    long timer_tick;
    char devname[IFNAMSIZ];
    char nodename[MAXHOSTNAMELEN];
    char conf_path[PATH_MAX];
    char ifup[NAME_MAX];
    char ca[NAME_MAX];
    char cert[NAME_MAX];
    char key[NAME_MAX];
} conf_t;

struct conf_operator
{
    int (*load_conf)(conf_t *conf, int argc, char *argv[]);
    void (*free_conf)(conf_t *v);
    void (*dump)(conf_t *v);
};
extern struct conf_operator Conf;
#endif
