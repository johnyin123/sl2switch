#include "l2switch.h"
#include "conf.h"
#include <errno.h>

#define myself        (Tun.getmac(tdev))
/*******cli**********************************/
static int client_error(ev_event_t *ev)
{
    inner_log(ALERT, "client error. close it %d (%d)",AsyncSocket.check(ev->fd), ev->fd);
    peer_t *peer = Event.ev_get_ctx(ev);
    connection_t *c = &peer->c;
    conf_t *cfg = AsyncSocket.get_ctx(c);
    /* delete peer from list */
    Peer.delpeer(&cfg->event_loop, peer);
    mem_free(peer);
    return EXIT_SUCCESS;
}

static int client_writer(ev_event_t *ev)
{
    peer_t *peer = Event.ev_get_ctx(ev);
    connection_t *c = &peer->c;
    conf_t *cfg = AsyncSocket.get_ctx(c);
    //tundev_t *tdev = cfg->tdev;
#ifdef HAVE_TLS
    if(!c->handshaked)
    {
        if(EXIT_SUCCESS != tls_handshake(c))
            return client_error(ev); /*EXIT_FAILURE, so close, delete peer*/
        if(c->handshaked)
        {
            inner_log(INFO, "SSL handshake OK %s(%X:%d) %d", peer->nodename, getpeer_ip(peer), getpeer_port(peer), AsyncSocket.getfd(&peer->c));
            //dump_peer(stderr, c);
        }
    }
    else
#endif
        Event.ev_mod(&cfg->event_loop, ev, EVENT_READ);
    return EXIT_SUCCESS;
}

static int client_reader(ev_event_t *ev)
{
    l2switch_pkt_t vpkt;
    uint64_t smac;
    ssize_t n;
    const char *buf;
    peer_t *peer = Event.ev_get_ctx(ev);
    connection_t *c = &peer->c;
    conf_t *cfg = AsyncSocket.get_ctx(c);
    tundev_t *tdev = &cfg->tdev;

#ifdef HAVE_TLS
    if(!c->handshaked)
    {
        if(EXIT_SUCCESS != tls_handshake(c))
            return client_error(ev); /*EXIT_FAILURE, so close, delete peer*/
        if(c->handshaked)
        {
            inner_log(INFO, "SSL handshake OK %s(%X:%d) %d", peer->nodename, getpeer_ip(peer), getpeer_port(peer), AsyncSocket.getfd(&peer->c));
            //dump_peer(stderr, c);
        }
    }
#endif
    while(1)
    {
        if (AsyncSocket.read(c) < 0)
            return client_error(ev); /*EXIT_FAILURE, so close, delete peer*/
        if((n = AsyncSocket.peekbuf(c, &buf))<MVPN_HDR_LEN) /*min size of cfg_pkt_t*/
            return EXIT_SUCCESS;
        if(!dec_l2switch_hdr(buf, &vpkt.hdr))
        {
            inner_log(ALERT, "check vmpn header failed (%d) = %Zu (%02x%02x%02x%02x)", AsyncSocket.getfd(c), n, *buf, *(buf+1), *(buf+2), *(buf+3));
            return client_error(ev); /*EXIT_FAILURE, so close, delete peer*/
        }
        if(vpkt.hdr.len + MVPN_HDR_LEN > n)
            return EXIT_SUCCESS;
        /* a package in socket buf */
        AsyncSocket.getbuf(c, (char *)&vpkt, vpkt.hdr.len + MVPN_HDR_LEN);
        //if(is_arp(&vpkt.ethpkt)) /* ipv6 用的ICMPv6 type 135和type=136来替代IPv4的ARP*/
        {
            smac = mac_src(&vpkt.ethpkt);
            /*Ethernet 交换机是根据Ethernet包中的源MAC地址来更新“MAC地址—端口号表*/
            if(peer->mac != smac)
            {
                inner_log(DEBUG, "MAC_ADDRESS: update %Zx to %Zx peer %s(%X:%d) changed!!", smac, peer->mac, peer->nodename, getpeer_ip(peer), getpeer_port(peer));
                peer->last_seen = time(NULL);
                peer->mac = smac;
            }
        }
        n = Tun.write(tdev, (char *)&vpkt.ethpkt, vpkt.hdr.len);
    }
    return EXIT_SUCCESS;
}

/*******tun**********************************/
static int recv_pkt(tundev_t *tdev, l2switch_pkt_t *vpkt)
{
    int size;
#if USE_TUN
    size = Tun.read(tdev, (void *)&vpkt->ethpkt.data, sizeof(pkt->data));
#else
    size = Tun.read(tdev, (void *)&vpkt->ethpkt, sizeof(ether_pkt_t));
#endif
    if (size <= 0)
    {
        inner_log(ERROR, "error while reading tun/tap");
        return EXIT_FAILURE;
    }
    enc_l2switch_hdr(size, &vpkt->hdr);
#if USE_TUN
    vpkt->hdr.len += ETH_HDRLEN;
    // assume ipv4
    *((char *)&vpkt->ethpkt + 12) = 0x08;
    *((char *)&vpkt->ethpkt + 13) = 0x00;
    if (!tun_to_tap(vpkt))
    {
        return EXIT_FAILURE;
    }
#endif
    return EXIT_SUCCESS;
}
static void broadcast_peers(conf_t *cfg, l2switch_pkt_t *vpkt)
{
    int nsend, len;
    peer_t *peer, *tmp;
    const char *buf  = (const char *)vpkt;
    int needsend = vpkt->hdr.len + MVPN_HDR_LEN;
    list_for_each_safe(peer, tmp, &cfg->peers.link, link)
    {
#ifdef HAVE_TLS
        if(!peer->c.handshaked)
            continue;
#endif
        nsend = 0;
        while(nsend < needsend)
        {
            if((len = AsyncSocket.write(&peer->c, buf + nsend, needsend - nsend)) > 0)
            {
                nsend += len;
            }
            else
            {
                if(errno == EAGAIN)
                    continue;
                inner_log(EMERG, "broadcast_peers error!!!![%s] %x:%d (%X:%s)", peer->nodename, getpeer_ip(peer), getpeer_port(peer), errno, strerror(errno));
                break;
            }
        }
    }
}
static void send_peer(conf_t *cfg, l2switch_pkt_t *vpkt, uint64_t mac)
{
    int nsend, len;
    peer_t *peer, *tmp;
    const char *buf  = (const char *)vpkt;
    int needsend = vpkt->hdr.len + MVPN_HDR_LEN;
    list_for_each_safe(peer, tmp, &cfg->peers.link, link)
    {
        if(peer->mac != mac)
            continue;
#ifdef HAVE_TLS
        if(!peer->c.handshaked)
            return;
#endif
        nsend = 0;
        while(nsend < needsend)
        {
            if((len = AsyncSocket.write(&peer->c, buf + nsend, needsend - nsend)) > 0)
            {
                nsend += len;
            }
            else
            {
                if(errno == EAGAIN)
                    continue;
                inner_log(EMERG, "send_peer[%s(mac:%Zx)] %s:%d (%X:%s)", peer->nodename, peer->mac, getpeer_ip(peer), getpeer_port(peer), errno, strerror(errno));
                break;
            }
        }
        /* only send to the first peer */
        return;
    }
}
static int tun_reader(ev_event_t *ev)
{
    l2switch_pkt_t vpkt;
    uint64_t smac, dmac;
    tundev_t *tdev = Event.ev_get_ctx(ev);
    conf_t *cfg = Tun.get_ctx(tdev);
    if(recv_pkt(tdev, &vpkt) == EXIT_FAILURE)
        return EXIT_SUCCESS;
    smac = mac_src(&vpkt.ethpkt);
    dmac = mac_dst(&vpkt.ethpkt);
    //if(dmac == BROADCAST_MAC)
    if(is_multi_broadcast(dmac))
        broadcast_peers(cfg, &vpkt);
    else if(smac == myself)
        send_peer(cfg, &vpkt, dmac);
    else
        inner_log(ERROR, "tun_mac=%Zx, smac=%Zx, dmac=%Zx: drop!!", tdev->mac, smac, dmac);
    return EXIT_SUCCESS;
}

/*******srv**********************************/
static int accept_reader(ev_event_t *ev)
{
    connection_t *srv = Event.ev_get_ctx(ev);
    conf_t *cfg = AsyncSocket.get_ctx(srv);
    peer_t *peer = mem_malloc(sizeof(peer_t));
    connection_t *c = &peer->c;
    if (AsyncSocket.accept(srv, c) == EXIT_SUCCESS)
    {
        /*add cfg in client socket private data*/
        if(0 != settcpnodelay(AsyncSocket.getfd(c)))
        {
            inner_log(ERROR, "incoming set_nodelay error(%d) %s", errno, strerror(errno));
        }
        AsyncSocket.set_ctx(c, cfg);
        if(Peer.addpeer(&cfg->event_loop, &cfg->peers, "incoming", peer, client_reader, NULL, client_error, EVENT_READ) == EXIT_SUCCESS)
        {
            return EXIT_SUCCESS;
        }
    }
    /* delete peer from list */
    Peer.delpeer(&cfg->event_loop, peer);
    mem_free(peer);
    return EXIT_FAILURE;
}
#ifdef HAVE_TLS
void md5(char *input, char *result)
{
}
#endif
/*******timer**********************************/
static int l2switch_timer(ev_event_t *ev)
{
    bool found;
    char ipaddr[20];
    outgoing_t *out, *tmp_out;
    peer_t *peer, *tmp;
    conf_t *cfg = Event.ev_get_ctx(ev);
    list_for_each_safe(out, tmp_out, &cfg->outgoing.link, link)
    {
        found = false;
        list_for_each_safe(peer, tmp, &cfg->peers.link, link)
        {
            /* only on connecton to peer!incoming or outgoing */
            if((getpeer_ip(peer) == out->ipaddr) && (out->port == getpeer_port(peer)))
            {
                found = true;
                break;
            }
        }
        if(!found)
        {
            peer = mem_malloc(sizeof(peer_t));
            connection_t *c = &peer->c;
            if(AsyncSocket.socket(c, PF_INET, SOCK_STREAM, IPPROTO_IP) == EXIT_SUCCESS)
            {
#ifdef HAVE_TLS
                set_tls_ctx(c, cfg->srv.tls_ctx);
#endif
                if (AsyncSocket.connect(c, int2ip(out->ipaddr, ipaddr), out->port) == EXIT_SUCCESS)
                {
                    /*add cfg in client socket private data*/
                    if(0 != settcpnodelay(AsyncSocket.getfd(c)))
                    {
                        inner_log(ERROR, "incoming set_nodelay error(%d) %s", errno, strerror(errno));
                    }
                    AsyncSocket.set_ctx(c, cfg);
                    if(Peer.addpeer(&cfg->event_loop, &cfg->peers, "outgoing", peer, client_reader, client_writer, client_error, EVENT_RW) == EXIT_SUCCESS)
                    {
                        continue;
                    }
                }
                /* delete peer from list */
                Peer.delpeer(&cfg->event_loop, peer);
                mem_free(peer);
            }
        }
    }
    Peer.dump(stderr, &cfg->peers);
    if (ev)
        Event.ev_timer_update(ev, cfg->timer_tick);
    return EXIT_SUCCESS;
}

static ev_event_t *add_ev(conf_t *cfg, int fd, ev_handler reader, ev_handler writer, ev_handler error, int events, void *ctx)
{
    inner_log(DEBUG, "add_fd %d, add event.",  fd);
    ev_event_t *ev = mem_malloc(sizeof(ev_event_t));
    Event.ev_init(ev, fd, reader, writer, error, ctx);
    if(EXIT_SUCCESS == Event.ev_add(&cfg->event_loop, ev, events))
        return ev;
    Event.ev_final(ev);
    mem_free(ev);
    return NULL;
}
static void del_ev(conf_t *cfg, ev_event_t *ev)
{
    inner_log(DEBUG, "close_sock %d, delete event.",  ev->fd);
    Event.ev_del(&cfg->event_loop, ev);
    Event.ev_final(ev);
    mem_free(ev);
}
void mainloop(conf_t *cfg)
{
    peer_t *peer, *tmp;
    ev_event_t timer_ev, *srv_ev, *tun_ev;
    if(Event.ev_timer_add(&cfg->event_loop, &timer_ev, 3000, l2switch_timer, cfg) == EXIT_FAILURE)
    {
        inner_log(ERROR, "add timer error");
    }
    if((srv_ev = add_ev(cfg, AsyncSocket.getfd(&cfg->srv), accept_reader, NULL, NULL, EVENT_READ, &cfg->srv)) == NULL)
        return;
    if((tun_ev = add_ev(cfg, Tun.getfd(&cfg->tdev), tun_reader, NULL, NULL, EVENT_READ, &cfg->tdev)) == NULL)
        return;
    Event.loop_cycle(&cfg->event_loop, 5000);
    Event.ev_timer_del(&cfg->event_loop, &timer_ev);
    list_for_each_safe(peer, tmp, &cfg->peers.link, link)
    {
        Peer.delpeer(&cfg->event_loop, peer);
        mem_free(peer);
    }
    Event.ev_final(&timer_ev);
    del_ev(cfg, srv_ev);
    del_ev(cfg, tun_ev);
}

