#ifndef MYIP_UTILS_H
#define MYIP_UTILS_H

#include <stdio.h>

#define IP2STR_4(addr_str, size, ip) { \
    do { \
        snprintf(addr_str, size, "%d.%d.%d.%d",  \
            (ip >> 24) & 0xff, \
            (ip >> 16) & 0xff, \
            (ip >> 8) & 0xff, \
            ip & 0xff); \
    } while(0); \
}

#define IPH_PRINT_IP(iph) { \
    do { \
        char saddr[17]; \
        char daddr[17]; \
        memset(saddr, 0, sizeof(saddr)); \
        memset(daddr, 0, sizeof(daddr)); \
        IP2STR_4(saddr, sizeof(saddr), ntohl(iph->src_addr)); \
        IP2STR_4(daddr, sizeof(daddr), ntohl(iph->dst_addr)); \
        printf("------------------------------  saddr: %s, daddr: %s\n", saddr, daddr); \
    } while(0); \
}

static void ipaddr_to_str(char *addr_str, int size, unsigned int ip)
{
    snprintf(addr_str, size, "%d.%d.%d.%d", 
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff);
}


//  eth_type  arp 0x0806   ipv4 0x0800



#endif
