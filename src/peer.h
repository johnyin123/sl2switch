#ifndef ___PEER_H__
#define ___PEER_H__

#include "list.h"
#include "event.h"
#include "async_socket.h"
#include <sys/param.h>
typedef struct peer_t
{
    char nodename[MAXHOSTNAMELEN];
    uint64_t mac;
    time_t last_seen;
    connection_t c;
    ev_event_t ev;
    list_t link;
} peer_t;

#include <arpa/inet.h>
#define getpeer_ip(p)   (p->c.in_addr.sin_addr.s_addr)
#define getpeer_port(p) ntohs(p->c.in_addr.sin_port)

struct peer_operator
{
    int  (*addpeer)(ev_loop_t *evloop, peer_t *peer_header, const char *nodename, peer_t *peer, ev_handler reader, ev_handler writer, ev_handler error, int events);
    void (*delpeer)(ev_loop_t *evloop, peer_t *peer);
    void (*dump)(FILE *fp, peer_t *peers);
};
extern struct peer_operator Peer;
#endif
