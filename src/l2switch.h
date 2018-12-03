#ifndef __L2SWITCH_H__
#define __L2SWITCH_H__
/*-----------------------------------------------------------------------------*/
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define MAX_MTU           (1500 + 14)
#define IP_OVERHEAD       20    // size of a (normal) ip header
#define ETH_MAXSIZE       (MAX_MTU + IP_OVERHEAD)    // slightly too large, but who cares
/************************************************************
 * ETHERNET FRAME FORMAT
 *
 *      6           6           2       (var)       4       Bytes/Octets
 *  -----------------------------------------------------------------
 *  | dest      | source    | ether | payload   | CRC   |
 *  | mac addr  | mac addr  | type  |           |       |
 *  -----------------------------------------------------------------
 * VPN PACKET
 *  add 4bytes len, before ETHERNET FRAME
 ************************************************************/

/*Protocol ID*/
#define ETH_TYPE_IPv4                 0x0800    /* IPv4 */
#define ETH_TYPE_ARP                  0x0806    /* Address Resolution packet    */
#define ETH_TYPE_IPv6                 0x86DD    /* IPv6 */

#define ETH_ADDR_LEN                  6    /* # of octets in MAC addr  */
#define ETH_TYPE_LEN                  2    /* # of octets for type     */
#define ETH_HDRLEN                    14
typedef struct ether_pkt_t
{
    uint8_t mac_dst[ETH_ADDR_LEN];
    uint8_t mac_src[ETH_ADDR_LEN];
    uint16_t ethtype;
    uint8_t data[ETH_MAXSIZE - (ETH_ADDR_LEN + ETH_ADDR_LEN + ETH_TYPE_LEN)];
} __attribute__ ((__packed__)) ether_pkt_t;
/************************************************************
 * ARP FRAME HDR FORMAT
 *
 *      2      2         1          1          2         Bytes/Octets
 *  -----------------------------------------------
 *  | HW   | Proto | HW Addr  | Proto Addr | Op   |
 *  | Type | Type  |   Len    |    Len     | Code |
 *  -----------------------------------------------
 ************************************************************/
#define ARP_ETHERNET_TYPE 1    /* Ethernet 10/100Mbps */
#define ARP_REQUEST    1       /* request to resolve address */
#define ARP_REPLY      2       /* response to previous request */
#define ARP_REVREQUEST 3       /* request protocol address given hardware */
#define ARP_REVREPLY   4       /* response giving protocol address */
#define ARP_INVREQUEST 8       /* request to identify peer */
#define ARP_INVREPLY   9       /* response identifying peer */
#define ARP_NAK        10      /* NAK - only valif for ATM ARP */

#define ARP_HDRLEN     8

#define BROADCAST_MAC   0xFFFFFFFFFFFF
const static uint8_t broadcast_addr[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const static uint8_t multicast_addr[6] = { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */
const static uint8_t ipv6_multicast_addr[6] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x00 }; /* First 2 bytes are meaningful */

static inline bool is_multi_broadcast(uint64_t mac)
{
    bool is_broadcast =(memcmp(broadcast_addr, &mac, 6) == 0);
    bool is_multicast =(memcmp(multicast_addr, &mac, 3) == 0);
    bool is_ipv6_multicast =(memcmp(ipv6_multicast_addr, &mac, 2) == 0);
    return is_broadcast || is_multicast || is_ipv6_multicast;
}


typedef struct arp_pkt_t
{
    uint16_t arp_hw_type;
    uint16_t arp_proto_type;
    uint8_t arp_hw_addr_len;
    uint8_t arp_proto_addr_len;
    uint16_t arp_opcode;
} __attribute__ ((__packed__)) arp_pkt_t;

#define IPv4_ADDR_LEN                 4    /* Length of IPv4 addr */
typedef struct arp_IPv4_pkt_t
{
    arp_pkt_t arp_hdr;
    /* addresses */
    uint8_t arp_sender_hw_addr[ETH_ADDR_LEN];
    uint8_t arp_sender_proto_addr[IPv4_ADDR_LEN];
    uint8_t arp_target_hw_addr[ETH_ADDR_LEN];
    uint8_t arp_target_proto_addr[IPv4_ADDR_LEN];
} __attribute__ ((__packed__)) arp_IPv4_pkt_t;

/*--------------------*/
typedef struct l2switch_hdr_t
{
    uint16_t len;  /* sizeof ethpkt*/
    uint8_t ver;
    uint8_t dummy;
} __attribute__ ((__packed__)) l2switch_hdr_t;

#define PKT_VER         0xBE /*uint8_t*/
#define PKT_DUMMY       0xEF /*uint8_t*/
#define MVPN_HDR_LEN    (sizeof(l2switch_hdr_t)) /* 4 bytes, uint32_t*/

typedef struct l2switch_pkt_t
{
    l2switch_hdr_t hdr;
    ether_pkt_t ethpkt;
} __attribute__ ((__packed__)) l2switch_pkt_t;

static inline uint64_t mac_src(ether_pkt_t *p)
{
    /*same as tun_dev mac format*/
    uint64_t mac = 0;   /* 0xFFFFFFFFFFFF0000 */
    memcpy(&mac, p->mac_src, ETH_ADDR_LEN);
    return mac;
}
static inline uint64_t mac_dst(ether_pkt_t *p)
{
    uint64_t mac = 0;   /* 0xFFFFFFFFFFFF0000 */
    memcpy(&mac, p->mac_dst, ETH_ADDR_LEN);
    return mac;
}
static inline bool is_arp(ether_pkt_t *p)
{
    uint8_t *pkt = (uint8_t *)p;
    return pkt[12] == 0x08 && pkt[13] == 0x06    /* 0806 protocol        */
           && pkt[14] == 0x00 && pkt[15] == 0x01    /* 0001 hw_format       */
           && pkt[16] == 0x08 && pkt[17] == 0x00    /* 0800 prot_format     */
           && pkt[18] == 0x06 && pkt[19] == 0x04;    /* 06 hw_len 04 prot_len */
}
static inline bool dec_l2switch_hdr(const char *buf, l2switch_hdr_t *hdr)
{
    bcopy(buf, hdr, sizeof(l2switch_hdr_t));
    if(hdr->len==0 || hdr->len>sizeof(l2switch_pkt_t) || hdr->ver != PKT_VER || hdr->dummy != PKT_DUMMY)
        return false;
    return true;
}
static inline void enc_l2switch_hdr(uint16_t len, l2switch_hdr_t *hdr)
{
    hdr->len = len;
    hdr->ver = PKT_VER;
    hdr->dummy = PKT_DUMMY;
}
#include "misc.h"
#define dump_l2spkt(vpkt) _dump_l2spkt(vpkt, "[%s(%s:%d)]", __FUNCTION__, __FILE__, __LINE__)
static inline void _dump_l2spkt(l2switch_pkt_t *vpkt, const char *fmt, ...)
{
    va_list ap;
    char msg[1024];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    dump_hex(stderr, vpkt, /*vpkt->hdr.len+*/MVPN_HDR_LEN + ETH_HDRLEN, "[%s%s%s] conf_hdr + ether_hdr", "\x1B[32m", msg, "\033[0m");
    va_end(ap);
    ether_dump(&vpkt->ethpkt, vpkt->hdr.len);
}

/*--ip proto-------------------------*/
static inline uint16_t iplen(ether_pkt_t *p)
{
    uint8_t *pkt = (uint8_t *)p;
    return ((uint16_t) (((((pkt)[16] & 0xFF) << 8) | ((pkt)[17] & 0xFF)) + 4));
}
#include <arpa/inet.h>
static inline uint32_t ipv4_src(ether_pkt_t *p)
{
    uint8_t *pkt = (uint8_t *)p;
    return htonl(((pkt)[26] << 24 | (pkt)[27] << 16 | (pkt)[28] << 8 | (pkt)[29]));
}
static inline uint32_t ipv4_dst(ether_pkt_t *p)
{
    uint8_t *pkt = (uint8_t *)p;
    return htonl(((pkt)[30] << 24 | (pkt)[31] << 16 | (pkt)[32] << 8 | (pkt)[33]));
}
static inline bool is_ipv4(ether_pkt_t *p)
{
    uint8_t *pkt = (uint8_t *)p;
    return pkt[12] == 0x08 && pkt[13] == 0x00    /* IP */
           && (pkt[14] & 0xf0) == 0x40;    /* IPv4 */
}
static inline char *int2ip(uint32_t ip, char ipaddr[20])
{
    struct in_addr s;
    s.s_addr = ip;
    inet_ntop(AF_INET, (void *)&s, ipaddr, 16);
    return ipaddr;
}
#endif
