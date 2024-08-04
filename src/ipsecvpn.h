#ifndef _IPSECVPN_H_
#define _IPSECVPN_H_


int is_vpn_dp_pkt(struct rte_mbuf *pkt);
int ipsecvpn_process(struct rte_mbuf *pkt);

#endif

