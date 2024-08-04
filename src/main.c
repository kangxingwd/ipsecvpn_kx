#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>

#include "log.h"
#include "ipsecvpn.h"
#include "ip_utils.h"


/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD                  1024

/* Number of TX ring descriptors */
#define NB_TXD                  1024

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400

#define KNI_MAX_KTHREAD 32

#define MAX_CORE 128
#define MAX_PORTS 64
#define MAX_PROCESS 64

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr) \
		(uint8_t) (((addr) >> 24) & 0xFF),\
		(uint8_t) (((addr) >> 16) & 0xFF),\
		(uint8_t) (((addr) >> 8) & 0xFF),\
		(uint8_t) ((addr) & 0xFF)
#endif

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"\
                       "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr) \
	addr[0],  addr[1], addr[2],  addr[3], \
	addr[4],  addr[5], addr[6],  addr[7], \
	addr[8],  addr[9], addr[10], addr[11],\
	addr[12], addr[13],addr[14], addr[15]
#endif

struct mbuf_userdata
{
    uint8_t dp_rx_port;
	uint8_t dp_tx_port;
    uint8_t packet_rx_flags; 
    uint8_t packet_tx_flags; 
    uint8_t class_id;
    uint8_t owner;  
    uint16_t owner_function;
};
#define INIT_MBUF_USERDATA(m) ((m)->udata64 = 0)
#define SET_MBUF_RX_PORT(m, port_id) (((struct mbuf_userdata *)(&((m)->udata64)))->dp_rx_port = (port_id))
#define GET_MBUF_RX_PORT(m)        (((struct mbuf_userdata *)(&((m)->udata64)))->dp_rx_port)
#define SET_MBUF_TX_PORT(m, port_id) (((struct mbuf_userdata *)(&((m)->udata64)))->dp_tx_port = (port_id))
#define GET_MBUF_TX_PORT(m)        (((struct mbuf_userdata *)(&((m)->udata64)))->dp_tx_port)


enum PKT_RX_TYPE
{
	PKT_RX_FROM_NIC        = 1,
	PKT_RX_FROM_KNI,
	PKT_RX_FROM_VPN,
	PKT_RX_TYPE_MAX
};
#define INIT_MBUF_RX_FLAG(m)       (((struct mbuf_userdata *)(&((m)->udata64)))->packet_rx_flags = 0)
#define SET_MBUF_RX_FLAG(m, flags) (((struct mbuf_userdata *)(&((m)->udata64)))->packet_rx_flags = (flags))
#define GET_MBUF_RX_FLAG(m)        (((struct mbuf_userdata *)(&((m)->udata64)))->packet_rx_flags)

enum PKT_TX_TYPE
{
	PKT_TX_TO_NIC        = 1,
	PKT_TX_TO_KNI,
	PKT_TX_TO_VPN,
	PKT_TX_TYPE_MAX
};
#define INIT_MBUF_TX_FLAG(m)       (((struct mbuf_nsfocus_userdata *)(&((m)->udata64)))->packet_tx_flags = 0)
#define SET_MBUF_TX_FLAG(m, flags) (((struct mbuf_nsfocus_userdata *)(&((m)->udata64)))->packet_tx_flags = (flags))
#define GET_MBUF_TX_FLAG(m)        (((struct mbuf_nsfocus_userdata *)(&((m)->udata64)))->packet_tx_flags)

struct port_conf {
	uint16_t port_id;/* Port ID */
	struct rte_kni *kni; /* KNI context pointers */
	uint64_t rx_pkts_num;
	uint64_t tx_pkts_num;
} __rte_cache_aligned;

enum CORE_ROLE
{
    DP_RX = 1,
	DP_TX,
    DP_PROCESS,
    DP_MAX
};

struct lcore_conf {
	uint8_t use_flag;
	uint8_t role;
	struct rte_ring* ring;
} __rte_cache_aligned;

/* Mempool for mbufs */
struct rte_mempool * g_pktmbuf_pool = NULL;
struct rte_ring* g_dp_tx_ring = NULL;
struct rte_ring* g_dp_process_ring[MAX_PROCESS] = {0};
uint8_t g_dp_process_num = 0;

static struct lcore_conf g_lcore_conf[MAX_CORE] = {0};
static struct port_conf g_port_conf[MAX_PORTS] = {0};
static uint8_t g_port_num = 0;

static int monitor_links = 0;

int parse_conf(int argc, char** argv) {

	memset(g_lcore_conf, 0, sizeof(g_lcore_conf));

	g_lcore_conf[1].role = DP_RX;
	g_lcore_conf[1].use_flag = 1;

	g_lcore_conf[2].role = DP_TX;
	g_lcore_conf[2].use_flag = 1;

	g_lcore_conf[3].role = DP_PROCESS;
	g_lcore_conf[3].use_flag = 1;

	g_lcore_conf[4].role = DP_PROCESS;
	g_lcore_conf[4].use_flag = 1;

	// g_dp_process_num = 2;
	
	return 0;

}

static void init_kni(void)
{
	unsigned int num_of_kni_ports = 4;
	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
}

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static void init_dpdk_port(uint16_t port)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	uint16_t nb_txd = NB_TXD;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_conf local_port_conf = port_conf;

	/* Initialise device and RX/TX queues */
	RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
	fflush(stdout);
	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	ret = rte_eth_dev_configure(port, 1, 1, &local_port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
		            (unsigned)port, ret);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned)port, ret);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port, 0, nb_rxd,
		rte_eth_dev_socket_id(port), &rxq_conf, g_pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
				"port%u (%d)\n", (unsigned)port, ret);

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port, 0, nb_txd,
		rte_eth_dev_socket_id(port), &txq_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
				"port%u (%d)\n", (unsigned)port, ret);

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
						(unsigned)port, ret);


	rte_eth_promiscuous_enable(port);
}

static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > RTE_ETHER_MAX_LEN)
		conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
							KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned int)port_id,
				ret);

	rte_eth_dev_info_get(port_id, &dev_info);
	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
		rte_eth_dev_socket_id(port_id), &rxq_conf, g_pktmbuf_pool);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n",
				port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	// rte_atomic32_inc(&kni_pause);

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	// rte_atomic32_dec(&kni_pause);

	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);

	return ret;
}

static void
print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
	RTE_LOG(INFO, APP, "\t%s%s\n", name, buf);
}

/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure mac address of %d\n", port_id);
	print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					(struct rte_ether_addr *)mac_addr);
	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to config mac_addr for port %d\n",
			port_id);

	return ret;
}

static int kni_alloc(uint16_t port_id)
{
	// uint8_t i;
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct rte_kni_ops ops;
	struct rte_eth_dev_info dev_info;

	if (port_id >= RTE_MAX_ETHPORTS)
		return -1;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, "KNI_%u", port_id);
	conf.group_id = port_id;
	conf.mbuf_size = MAX_PACKET_SZ;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);

	/* Get the interface default mac address */
	rte_eth_macaddr_get(port_id, (struct rte_ether_addr *)&conf.mac_addr);

	rte_eth_dev_get_mtu(port_id, &conf.mtu);

	memset(&ops, 0, sizeof(ops));
	ops.port_id = port_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_interface;
	ops.config_mac_address = kni_config_mac_address;

	kni = rte_kni_alloc(g_pktmbuf_pool, &conf, &ops);
	if (!kni)
		rte_exit(EXIT_FAILURE, "Fail to create kni for port: %d\n", port_id);
	
	g_port_conf[port_id].kni = kni;

	return 0;
}

static int kni_free_kni(uint16_t port_id)
{
	uint8_t i;

	if (port_id >= RTE_MAX_ETHPORTS)
		return -1;

	if (g_port_conf[port_id].kni) {
		if (rte_kni_release(g_port_conf[port_id].kni) ) {
			printf("Fail to release kni\n");
		}
		g_port_conf[port_id].kni = NULL;
	}
	rte_eth_dev_stop(port_id);
	return 0;
}

#define ETHER_TYPE_8021Q_X86 0x0081
#define ETHER_TYPE_QINQ_X86 0x0091
#define ETHER_TYPE_ARP_X86 0x0608
#define ETHER_TYPE_IPv4_X86 0x0008 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6_X86 0xDD86 /**< IPv6 Protocol. */
#define ETHER_TYPE_MPLS_X86 0x4788 /**< mpls. */
#define ETHER_TYPE_MPLS_MULT_X86 0x4888 /**< mpls. */

#define IS_IPV4_PKT(m) (((struct rte_ether_hdr *)(rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *))->ether_type) == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))

int is_ipv4_pkt(struct rte_mbuf *pkt) 
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		return 1;
	}
	return 0;
}

uint8_t get_pkt_rss(struct rte_mbuf *pkt) 
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint16_t ether_type;
	uint32_t rss;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;

	if (ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		return 0;
	}

	ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	rss =  ((ipv4_hdr->src_addr >> 24)
			^ (ipv4_hdr->src_addr&0xffffff)
			^(ipv4_hdr->dst_addr >> 24)
			^ (ipv4_hdr->dst_addr&0xffffff)) % g_dp_process_num;

	return rss;
}

void send_to_process_ring(struct rte_mbuf **pkts_burst, unsigned nb_rx, uint8_t pkt_flag, uint8_t port_id)
{
	uint8_t i = 0;
	struct rte_mbuf *pkt = NULL;
	uint32_t rss = 0;
	char buf[64];

	if (nb_rx <= 0) {
		return;
	}

	for (i = 0; i < nb_rx; i++) {
		pkt = pkts_burst[i];
		INIT_MBUF_USERDATA(pkt);
		SET_MBUF_RX_FLAG(pkt, pkt_flag);
		SET_MBUF_RX_PORT(pkt, port_id);

		rss = get_pkt_rss(pkt);

		if (is_ipv4_pkt(pkt)) {
		// if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
			
			struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			LOG_DEBUG("%-14s port_id:%u [" IPv4_BYTES_FMT " -> " IPv4_BYTES_FMT "]" " next_proto_id:%u, rss:%u \n", 
				(pkt_flag == PKT_RX_FROM_NIC)?"RECV FROM NIC": "RECV FROM KNI",
				port_id,
				IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->src_addr)),
				IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)),
				ip_hdr->next_proto_id, 
				rss
			);
		}
		
		// LOG_DEBUG("%s port_id:%u ether_type:%04x\n", 
		// 	(pkt_flag == PKT_RX_FROM_NIC)?"FROM NIC": "FROM KNI",
		// 	port_id,
		// 	rte_be_to_cpu_16(((struct rte_ether_hdr* )rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *))->ether_type)
		// );

		if ((rte_ring_enqueue(g_dp_process_ring[rss], (void *)pkt)) != 0 ) {
			rte_pktmbuf_free(pkt);
		}
	}
}

void send_to_kni(struct rte_mbuf *pkt) 
{
	// unsigned lcore_id = rte_lcore_id();
	uint8_t port_id = GET_MBUF_RX_PORT(pkt);
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	pkts_burst[0] = pkt;

	if (is_ipv4_pkt(pkt)) {
		struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
		LOG_DEBUG("%-14s port_id:%u [" IPv4_BYTES_FMT " -> " IPv4_BYTES_FMT "]" " next_proto_id:%u \n", 
			"SEND TO KNI",
			port_id,
			IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->src_addr)), 
			IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)), 
			ip_hdr->next_proto_id
		);
	}

	// LOG_DEBUG("port_id:%u ether_type:%04x\n", 
	// 	port_id,
	// 	rte_be_to_cpu_16(((struct rte_ether_hdr* )rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *))->ether_type)
	// );

	rte_kni_tx_burst(g_port_conf[port_id].kni, pkts_burst, 1);
}

void send_to_nic(struct rte_mbuf *pkt) 
{
	// unsigned lcore_id = rte_lcore_id();
	uint8_t port_id = GET_MBUF_TX_PORT(pkt);
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	pkts_burst[0] = pkt;

	if (is_ipv4_pkt(pkt)) {
		struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
		LOG_DEBUG("%-14s port_id:%u [" IPv4_BYTES_FMT " -> " IPv4_BYTES_FMT "]" " next_proto_id:%u \n", 
			"SEND TO NIC",
			port_id,
			IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->src_addr)), 
			IPv4_BYTES(rte_be_to_cpu_32(ip_hdr->dst_addr)), 
			ip_hdr->next_proto_id
		);
	}

	// LOG_DEBUG("port_id:%u ether_type:%04x\n", 
	// 	port_id,
	// 	rte_be_to_cpu_16(((struct rte_ether_hdr* )rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *))->ether_type)
	// );

	rte_eth_tx_burst(port_id, 0, pkts_burst, 1);
}

static void dp_rx(void) {
	uint16_t port;
	unsigned nb_rx;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	unsigned lcore_id = rte_lcore_id();

	printf("lcore_id %u role RX\n", lcore_id);

	while (1) {
		RTE_ETH_FOREACH_DEV(port) {
			
			// recve from nic
			nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, PKT_BURST_SZ);
			if (unlikely(nb_rx > PKT_BURST_SZ)) {
				RTE_LOG(ERR, APP, "Error receiving from eth\n");
				printf("Error receiving from eth, nb_rx = %u\n", nb_rx);
				return;
			}
			send_to_process_ring(pkts_burst, nb_rx, PKT_RX_FROM_NIC, port);

			// rx from kni
			nb_rx = rte_kni_rx_burst(g_port_conf[port].kni, pkts_burst, PKT_BURST_SZ);
			if (unlikely(nb_rx > PKT_BURST_SZ)) {
				RTE_LOG(ERR, APP, "Error receiving from KNI\n");
				printf("Error receiving from KNI, nb_rx = %u\n", nb_rx);
				return;
			}
			// printf("RX from kni %u nb = %u\n", port, nb_rx);
			send_to_process_ring(pkts_burst, nb_rx, PKT_RX_FROM_KNI, port);

			rte_kni_handle_request(g_port_conf[port].kni);
		}
	}
}

static void dp_process(void) {
	unsigned lcore_id = rte_lcore_id();
	struct rte_mbuf * pkts[PKT_BURST_SZ];
	uint16_t nb_rx = 0;
	struct rte_ring * proc_ring = g_lcore_conf[lcore_id].ring;
	uint16_t rx_pkts = 0;
	uint16_t i = 0;
	uint8_t pkt_rx_flag;
	struct rte_mbuf *pkt;

	struct rte_mbuf *to_kni_pkts[PKT_BURST_SZ];
	struct rte_mbuf *to_nic_pkts[PKT_BURST_SZ];
	int to_kni_num = 0;
	int to_nic_num = 0;

	printf("lcore_id %u role PROCESS\n", lcore_id);

	while (1) {
		
		// dequeue from process ring
		rx_pkts = (uint16_t)RTE_MIN(rte_ring_count(proc_ring), (uint32_t)PKT_BURST_SZ);
		if (rx_pkts == 0) {
			continue;
		}

		nb_rx = rte_ring_dequeue_bulk(proc_ring, (void *)pkts, rx_pkts, NULL);
		for (i = 0; i < nb_rx; i++) {
			pkt = pkts[i];
			pkt_rx_flag = GET_MBUF_RX_FLAG(pkt);

			if (pkt_rx_flag == PKT_RX_FROM_NIC) {
				if (is_vpn_dp_pkt(pkt)) {
					ipsecvpn_process(pkt);

				} else {
					send_to_kni(pkt);
					// to_kni_pkts[to_kni_num++] = pkt;
				}

			} else if (pkt_rx_flag == PKT_RX_FROM_KNI) {

				if (is_vpn_dp_pkt(pkt)) {
					ipsecvpn_process(pkt);

				} else {
					
					// TODO: route, find tx port
					// uint8_t tx_port = (GET_MBUF_RX_PORT(pkt) == 0)?1:0;
					SET_MBUF_TX_PORT(pkt, GET_MBUF_RX_PORT(pkt));
					
					// send to NIC
					send_to_nic(pkt);
					// to_nic_pkts[to_nic_num++] = pkt;
				}

			} else {
				printf("pkt no rx flag\n");
			}
		}

		// send_to_kni(to_kni_pkts, to_kni_num);
		// send_to_nic(to_nic_pkts, to_nic_num);

		// vpn 500/4500 conn process
			// send to tx ring,  flag: to kni

		// vpn enc/dec process 
			// send to tx ring;  flag: to nic
	}
}

static void dp_tx(void) {
	unsigned lcore_id = rte_lcore_id();

	printf("lcore_id %u role TX\n", lcore_id);

	while (1) {

		// dequeue from tx ring

		// send to kni

		// send to nic


	}

}

static int main_loop(__rte_unused void *arg)
{
	unsigned lcore_id = rte_lcore_id();
	uint8_t role = g_lcore_conf[lcore_id].role;

	if (role == DP_RX) {
		dp_rx();
	} else if (role == DP_TX) {
		dp_tx();
	} else if (role == DP_PROCESS) {
		dp_process();
	} else {
		printf("Lcore %u has nothong to do!\n", lcore_id);
	}

	return 0;
}

#define RING_SIZE 1024
#define RING_NAME_SIZE 256
#define PROCESS_RING "process_ring_%d"

int init_dpdk(int argc, char** argv) {
	int ret;
	uint16_t nb_sys_ports;
	struct rte_ring *ring = NULL;
	int i = 0;
	char ring_name[RING_NAME_SIZE];

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		printf("rte_eal_init failed!\n");
		return -1;
	}

	nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0) {
		printf("no avail port! No supported Ethernet device found!\n");
		return -1;
	}

	g_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (g_pktmbuf_pool == NULL) {
		printf("Could not initialise mbuf pool\n");
		return -1;
	}

	// init tx ring
	g_dp_tx_ring = rte_ring_create("dp_tx_ring", RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
	if (g_dp_tx_ring == NULL) {
		printf("dp_tx_ring creat failed!\n");
		return -1;
	}

	g_dp_process_num = 0;
	for (i = 0; i < MAX_CORE; i++) {
		if (g_lcore_conf[i].use_flag && g_lcore_conf[i].role == DP_PROCESS) {
			
			snprintf(ring_name, RING_NAME_SIZE, PROCESS_RING, i);
			ring = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				printf("creat process ring failed\n");
				return -1;
			}
			printf("init process ring success, %s\n", ring_name);
			
			g_dp_process_ring[g_dp_process_num] = ring;
			g_lcore_conf[i].ring = ring;
			g_dp_process_num++;
		}
		ring = NULL;
	}

	return 0;
}

int init_port(void)
{
	uint16_t port;

	init_kni();

	RTE_ETH_FOREACH_DEV(port) {
		printf("init_port port: %u\n", port);

		init_dpdk_port(port);

		if (port >= RTE_MAX_ETHPORTS) {
			printf("Can not use more than %d ports for kni\n", RTE_MAX_ETHPORTS);
			return -1;
		}

		kni_alloc(port);

		g_port_conf[g_port_num].port_id = port;
		g_port_conf[g_port_num].rx_pkts_num = 0;
		g_port_conf[g_port_num].tx_pkts_num = 0;
		g_port_num++;
	}

	return 0;
}

static void log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
	if (kni == NULL || link == NULL)
		return;

	if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
		RTE_LOG(INFO, APP, "%s NIC Link is Up %d Mbps %s %s.\n",
			rte_kni_get_name(kni),
			link->link_speed,
			link->link_autoneg ?  "(AutoNeg)" : "(Fixed)",
			link->link_duplex ?  "Full Duplex" : "Half Duplex");
	} else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
		RTE_LOG(INFO, APP, "%s NIC Link is Down.\n",
			rte_kni_get_name(kni));
	}
}

static void *monitor_all_ports_link_status(void)
{
	uint16_t portid;
	struct rte_eth_link link;
	unsigned int i;
	int prev;

	while (1) {
		rte_delay_ms(500);
		RTE_ETH_FOREACH_DEV(portid) {
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			prev = rte_kni_update_link(g_port_conf[portid].kni, link.link_status);
			log_link_state(g_port_conf[portid].kni, prev, &link);
		}
	}
	return NULL;
}

int main(int argc, char** argv)
{
	int ret;
	unsigned i;
	uint16_t port;
	pthread_t kni_link_tid;
	void *retval;

	LOG_INIT(LOG_MODE_STDOUT, LOG_LEVEL_DEBUG, NULL);
	LOG_DEBUG("main start ... %s ", "start");

	ret = parse_conf(argc, argv);
	if (ret != 0) {
		printf(" parse conf failed! \n");
		return -1;
	}
	
	ret = init_dpdk(argc, argv);
	if (ret != 0) {
		printf(" init dpdk failed! \n");
		return -1;
	}
	
	ret = init_port();
	if (ret != 0) {
		printf(" init port failed! \n");
		return -1;
	}

	monitor_links = 1;
	ret = rte_ctrl_thread_create(&kni_link_tid, "KNI link status check", NULL, monitor_all_ports_link_status, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Could not create link status thread!\n");

	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}

	monitor_links = 0;
	pthread_join(kni_link_tid, &retval);

	RTE_ETH_FOREACH_DEV(port) {
		kni_free_kni(port);
	}

	return 0;
}