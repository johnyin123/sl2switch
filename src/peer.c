#include "peer.h"
static void _removepeer(ev_loop_t *evloop, peer_t *peer)
{
    assert(peer);
    inner_log(INFO, "delpeer %s(%X:%d) %d", peer->nodename, getpeer_ip(peer), getpeer_port(peer), AsyncSocket.getfd(&peer->c));
    Event.ev_del(evloop, &peer->ev);
    Event.ev_final(&peer->ev);
    list_remove(&peer->link);
    return;
}
static int _addpeer(ev_loop_t *evloop, peer_t *peer_header, const char *nodename, peer_t *peer, ev_handler reader, ev_handler writer, ev_handler error, int events)
{
    assert(peer);
    strncpy(peer->nodename, nodename, MAXHOSTNAMELEN);
    peer->last_seen = 0;//time(NULL);
    inner_log(INFO, "addpeer %s(%X:%d) %d", peer->nodename, getpeer_ip(peer), getpeer_port(peer), AsyncSocket.getfd(&peer->c));
    /*client socket(accepted, connect out), use peer as ctx */
    Event.ev_init(&peer->ev, AsyncSocket.getfd(&peer->c), reader, writer, error, peer);
    if(EXIT_SUCCESS == Event.ev_add(evloop, &peer->ev, events))
    {
        list_append(&(peer_header->link), &peer->link);
        return EXIT_SUCCESS;
    }
    Event.ev_final(&peer->ev);
    return EXIT_FAILURE;
}
#include <arpa/inet.h>
#include "misc.h"

static void _dumppeers(FILE *fp, peer_t *peers)
{
    struct in_addr s;
    char ipaddr[20];
    peer_t *peer;
    int cnt = 0;
    fprintf(fp, "-----------------------------------------\n");
    list_for_each_entry(peer, &peers->link, link)
    {
        cnt++;
        s.s_addr = getpeer_ip(peer);
        fprintf(fp, "%d:mac[%Zx][%s] %X(%s):%d(%d) ", cnt, peer->mac, peer->nodename, getpeer_ip(peer), inet_ntop(AF_INET, &s, ipaddr, 16), getpeer_port(peer), AsyncSocket.getfd(&peer->c));
        if(EXIT_SUCCESS == getsockerror(AsyncSocket.getfd(&peer->c)))
        {
            fprintf(fp, " [EST");
#ifdef HAVE_TLS
            fprintf(fp, "%s", peer->c.accept ? "(SSL OK)" : "(SSL NEGO)");
#endif
            fprintf(fp, "]\n");
        }
        else
        {
            fprintf(fp, " [DIS]\n");
        }
    }
    fprintf(fp, "-----------------------------------------\n");
}
struct peer_operator Peer =
{
    .addpeer   = _addpeer,
    .delpeer   = _removepeer,
    .dump      = _dumppeers,
};

