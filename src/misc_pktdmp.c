#include "l2switch.h"
#include <stddef.h>

static void human_readable_ipv4(void *pkt_ip, char *ip, int size)
{
    uint8_t *orig_ip = pkt_ip;
    bzero(ip, size);
    snprintf(ip, size, "%d.%d.%d.%d", orig_ip[0], orig_ip[1], orig_ip[2], orig_ip[3]);
}

static void human_readable_mac(void *pkt_mac, char *mac, int size)
{
    uint8_t *orig_mac = pkt_mac;
    bzero(mac, size);
    snprintf(mac, size, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", orig_mac[0], orig_mac[1], orig_mac[2], orig_mac[3], orig_mac[4], orig_mac[5]);
}

static void convert_eth_type(uint16_t type, char *eth_type, int size)
{
    switch (type)
    {
    case ETH_TYPE_IPv4:
        snprintf((char *)eth_type, size, "IPv4");
        break;
    case ETH_TYPE_IPv6:
        snprintf((char *)eth_type, size, "IPv6");
        break;
    case ETH_TYPE_ARP:
        snprintf((char *)eth_type, size, "ARP");
        break;
    default:
        snprintf((char *)eth_type, size, "%04X", type);
        break;
    }
}

static void convert_arp_type(uint16_t opcode, char *arp_type, int size)
{
    switch (opcode)
    {
    case ARP_REQUEST:
        snprintf((char *)arp_type, size, "Reqst");
        break;
    case ARP_REPLY:
        snprintf((char *)arp_type, size, "Reply");
        break;
    }
}

static void dump_arp_pkt(void *buf, int size)
{
    arp_IPv4_pkt_t *pkt = buf;
    char arp_type[8];
    char mac_src[24];
    char mac_dst[24];
    char ip_src[24];
    char ip_dst[24];
    if (ntohs(pkt->arp_hdr.arp_hw_type) != ARP_ETHERNET_TYPE)
    {
        inner_log(ERROR, "Not ethernet!!");
        return;
    }
    if (ntohs(pkt->arp_hdr.arp_proto_type) != ETH_TYPE_IPv4)
    {
        inner_log(ERROR, "Not IPv4!");
        return;
    }
    convert_arp_type(ntohs(pkt->arp_hdr.arp_opcode), arp_type, sizeof(arp_type));
    human_readable_mac(pkt->arp_sender_hw_addr, mac_src, sizeof(mac_src));
    human_readable_mac(pkt->arp_target_hw_addr, mac_dst, sizeof(mac_dst));
    human_readable_ipv4(pkt->arp_sender_proto_addr, ip_src, sizeof(ip_src));
    human_readable_ipv4(pkt->arp_target_proto_addr, ip_dst, sizeof(ip_dst));
    fprintf(stderr, "ARP (%5s) %s[%s] --> %s[%s]\n", arp_type, ip_src, mac_src, ip_dst, mac_dst);
}

void _ether_dump(void *buf, int size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    ether_pkt_t *pkt = buf;
    char mac_dst[24];
    char mac_src[24];
    char eth_type[6];
    uint16_t payload_type = ntohs(pkt->ethtype);
    convert_eth_type(payload_type, eth_type, sizeof(eth_type));
    human_readable_mac(pkt->mac_src, mac_src, sizeof(mac_src));
    human_readable_mac(pkt->mac_dst, mac_dst, sizeof(mac_dst));
    fprintf(stderr, "ether(%d bytes) %s(%04x) [%s] --> [%s]\n", size, eth_type, payload_type, mac_src, mac_dst);
    switch (payload_type)
    {
    case ETH_TYPE_IPv4:
        break;
    case ETH_TYPE_ARP:
        dump_arp_pkt(pkt->data, size - offsetof(ether_pkt_t, data));
        break;
    default:
        break;
    }
}
