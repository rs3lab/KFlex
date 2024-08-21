// SPDX-License-Identifier: GPL-2.0
#ifndef EKCACHE_BPF_EKC_COUNTSKETCH_BPF_H
#define EKCACHE_BPF_EKC_COUNTSKETCH_BPF_H

#include <bpf_experimental.bpf.h>
#include <bpf_helpers.bpf.h>
#include <countsketch_common.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define CHECK_BIT(var, pos) ((var) & (1 << (pos)))

#define NO_TEAR_ADD(x, val) WRITE_ONCE((x), READ_ONCE(x) + (val))
#define NO_TEAR_INC(x) NO_TEAR_ADD((x), 1)

/*
 *	IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
 *	and FCS/CRC (frame check sequence).
 */

#define ETH_ALEN 6         /* Octets in one ethernet addr	 */
#define ETH_TLEN 2         /* Octets in ethernet type field */
#define ETH_HLEN 14        /* Total octets in header.	 */
#define ETH_ZLEN 60        /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN 1500  /* Max. octets in payload	 */
#define ETH_FRAME_LEN 1514 /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN 4      /* Octets in the FCS		 */

#define ETH_MIN_MTU 68      /* Min IPv4 MTU per RFC791	*/
#define ETH_MAX_MTU 0xFFFFU /* 65535, same as IP_MAX_MTU	*/

/*
 *	These are the defined Ethernet Protocol ID's.
 */

#define ETH_P_LOOP 0x0060      /* Ethernet Loopback packet	*/
#define ETH_P_PUP 0x0200       /* Xerox PUP packet		*/
#define ETH_P_PUPAT 0x0201     /* Xerox PUP Addr Trans packet	*/
#define ETH_P_TSN 0x22F0       /* TSN (IEEE 1722) packet	*/
#define ETH_P_ERSPAN2 0x22EB   /* ERSPAN version 2 (type III)	*/
#define ETH_P_IP 0x0800        /* Internet Protocol packet	*/
#define ETH_P_X25 0x0805       /* CCITT X.25			*/
#define ETH_P_ARP 0x0806       /* Address Resolution packet	*/
#define ETH_P_BPQ 0x08FF       /* G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IEEEPUP 0x0a00   /* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT 0x0a01 /* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_BATMAN 0x4305    /* B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DEC 0x6000       /* DEC Assigned proto           */
#define ETH_P_DNA_DL 0x6001    /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC 0x6002    /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT 0x6003    /* DEC DNA Routing              */
#define ETH_P_LAT 0x6004       /* DEC LAT                      */
#define ETH_P_DIAG 0x6005      /* DEC Diagnostics              */
#define ETH_P_CUST 0x6006      /* DEC Customer use             */
#define ETH_P_SCA 0x6007       /* DEC Systems Comms Arch       */
#define ETH_P_TEB 0x6558       /* Trans Ether Bridging		*/
#define ETH_P_RARP 0x8035      /* Reverse Addr Res packet	*/
#define ETH_P_ATALK 0x809B     /* Appletalk DDP		*/
#define ETH_P_AARP 0x80F3      /* Appletalk AARP		*/
#define ETH_P_8021Q 0x8100     /* 802.1Q VLAN Extended Header  */
#define ETH_P_ERSPAN 0x88BE    /* ERSPAN type II		*/
#define ETH_P_IPX 0x8137       /* IPX over DIX			*/
#define ETH_P_IPV6 0x86DD      /* IPv6 over bluebook		*/
#define ETH_P_PAUSE 0x8808     /* IEEE Pause frames. See 802.3 31B */
#define ETH_P_SLOW 0x8809      /* Slow Protocol. See 802.3ad 43B */
#define ETH_P_WCCP                                               \
  0x883E                      /* Web-cache coordination protocol \
                               * defined in draft-wilson-wrec-wccp-v2-00.txt */
#define ETH_P_MPLS_UC 0x8847  /* MPLS Unicast traffic		*/
#define ETH_P_MPLS_MC 0x8848  /* MPLS Multicast traffic	*/
#define ETH_P_ATMMPOA 0x884c  /* MultiProtocol Over ATM	*/
#define ETH_P_PPP_DISC 0x8863 /* PPPoE discovery messages     */
#define ETH_P_PPP_SES 0x8864  /* PPPoE session messages	*/
#define ETH_P_LINK_CTL 0x886c /* HPNA, wlan link local tunnel */
#define ETH_P_ATMFATE                                       \
  0x8884                       /* Frame-based ATM Transport \
                                * over Ethernet             \
                                */
#define ETH_P_PAE 0x888E       /* Port Access Entity (IEEE 802.1X) */
#define ETH_P_PROFINET 0x8892  /* PROFINET			*/
#define ETH_P_REALTEK 0x8899   /* Multiple proprietary protocols */
#define ETH_P_AOE 0x88A2       /* ATA over Ethernet		*/
#define ETH_P_ETHERCAT 0x88A4  /* EtherCAT			*/
#define ETH_P_8021AD 0x88A8    /* 802.1ad Service VLAN		*/
#define ETH_P_802_EX1 0x88B5   /* 802.1 Local Experimental 1.  */
#define ETH_P_PREAUTH 0x88C7   /* 802.11 Preauthentication */
#define ETH_P_TIPC 0x88CA      /* TIPC 			*/
#define ETH_P_LLDP 0x88CC      /* Link Layer Discovery Protocol */
#define ETH_P_MRP 0x88E3       /* Media Redundancy Protocol	*/
#define ETH_P_MACSEC 0x88E5    /* 802.1ae MACsec */
#define ETH_P_8021AH 0x88E7    /* 802.1ah Backbone Service Tag */
#define ETH_P_MVRP 0x88F5      /* 802.1Q MVRP                  */
#define ETH_P_1588 0x88F7      /* IEEE 1588 Timesync */
#define ETH_P_NCSI 0x88F8      /* NCSI protocol		*/
#define ETH_P_PRP 0x88FB       /* IEC 62439-3 PRP/HSRv0	*/
#define ETH_P_CFM 0x8902       /* Connectivity Fault Management */
#define ETH_P_FCOE 0x8906      /* Fibre Channel over Ethernet  */
#define ETH_P_IBOE 0x8915      /* Infiniband over Ethernet	*/
#define ETH_P_TDLS 0x890D      /* TDLS */
#define ETH_P_FIP 0x8914       /* FCoE Initialization Protocol */
#define ETH_P_80221 0x8917     /* IEEE 802.21 Media Independent Handover Protocol */
#define ETH_P_HSR 0x892F       /* IEC 62439-3 HSRv1	*/
#define ETH_P_NSH 0x894F       /* Network Service Header */
#define ETH_P_LOOPBACK 0x9000  /* Ethernet loopback packet, per IEEE 802.3 */
#define ETH_P_QINQ1 0x9100     /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ2 0x9200     /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ3 0x9300     /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_EDSA 0xDADA      /* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DSA_8021Q 0xDADB /* Fake VLAN Header for DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DSA_A5PSW 0xE001 /* A5PSW Tag Value [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IFE 0xED3E       /* ForCES inter-FE LFB type */
#define ETH_P_AF_IUCV 0xFBFB   /* IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ] */

#define ETH_P_802_3_MIN                                               \
  0x0600 /* If the value in the ethernet type is more than this value \
          * then the frame is Ethernet II. Else it is 802.3 */

/*
 *	Non DIX types. Won't clash for 1500 types.
 */

#define ETH_P_802_3 0x0001      /* Dummy type for 802.3 frames  */
#define ETH_P_AX25 0x0002       /* Dummy protocol id for AX.25  */
#define ETH_P_ALL 0x0003        /* Every packet (be careful!!!) */
#define ETH_P_802_2 0x0004      /* 802.2 frames 		*/
#define ETH_P_SNAP 0x0005       /* Internal only		*/
#define ETH_P_DDCMP 0x0006      /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP 0x0007    /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP 0x0008     /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009  /* Localtalk pseudo type 	*/
#define ETH_P_CAN 0x000C        /* CAN: Controller Area Network */
#define ETH_P_CANFD 0x000D      /* CANFD: CAN flexible data rate*/
#define ETH_P_CANXL 0x000E      /* CANXL: eXtended frame Length */
#define ETH_P_PPPTALK 0x0010    /* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2 0x0011   /* 802.2 frames 		*/
#define ETH_P_MOBITEX 0x0015    /* Mobitex (kaz@cafe.net)	*/
#define ETH_P_CONTROL 0x0016    /* Card specific control frames */
#define ETH_P_IRDA 0x0017       /* Linux-IrDA			*/
#define ETH_P_ECONET 0x0018     /* Acorn Econet			*/
#define ETH_P_HDLC 0x0019       /* HDLC frames			*/
#define ETH_P_ARCNET 0x001A     /* 1A for ArcNet :-)            */
#define ETH_P_DSA 0x001B        /* Distributed Switch Arch.	*/
#define ETH_P_TRAILER 0x001C    /* Trailer switch tagging	*/
#define ETH_P_PHONET 0x00F5     /* Nokia Phonet frames          */
#define ETH_P_IEEE802154 0x00F6 /* IEEE802.15.4 frame		*/
#define ETH_P_CAIF 0x00F7       /* ST-Ericsson CAIF protocol	*/
#define ETH_P_XDSA 0x00F8       /* Multiplexed DSA protocol	*/
#define ETH_P_MAP                     \
  0x00F9 /* Qualcomm multiplexing and \
          * aggregation protocol      \
          */
#define ETH_P_MCTP                         \
  0x00FA /* Management component transport \
          * protocol packets               \
          */

struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));

/*The struct defined in tcp.h lets flags be accessed only one by one,
 *it is not needed here.*/
struct tcp_hdr {
  __be16 source;
  __be16 dest;
  __be32 seq;
  __be32 ack_seq;
  __u8 doff : 4, res1 : 4;
  __u8 flags;
  __be16 window;
  __sum16 check;
  __be16 urg_ptr;
} __attribute__((packed));

// Compression function for Merkle-Damgard construction.
// This function is generated using the framework provided.
static __u64 fasthash_mix(__u64 h) {
  h ^= h >> 23;
  h *= 0x2127599bf4325c37ULL;
  h ^= h >> 47;
  return h;
}

static __u64 fasthash64(const void *buf, __u64 len, __u64 seed) {
  const __u64 m = 0x880355f21e6d1965ULL;
  const __u64 *pos = (const __u64 *)buf;
  const __u64 *end = pos + (len / 8);
  const unsigned char *pos2;
  __u64 h = seed ^ (len * m);
  __u64 v;

  while (pos != end) {
    v = *pos++;
    h ^= fasthash_mix(v);
    h *= m;
  }

  pos2 = (const unsigned char *)pos;
  v = 0;

  switch (len & 7) {
    case 7:
      v ^= (__u64)pos2[6] << 48;
    case 6:
      v ^= (__u64)pos2[5] << 40;
    case 5:
      v ^= (__u64)pos2[4] << 32;
    case 4:
      v ^= (__u64)pos2[3] << 24;
    case 3:
      v ^= (__u64)pos2[2] << 16;
    case 2:
      v ^= (__u64)pos2[1] << 8;
    case 1:
      v ^= (__u64)pos2[0];
      h ^= fasthash_mix(v);
      h *= m;
  }

  return fasthash_mix(h);
}

// add element and determine count
static void __always_inline countsketch_add(struct countsketch *cs, void *element, __u64 len) {
  // Calculate just a single hash and re-use it to update and query the sketch
  uint64_t h = fasthash64(element, len, SEED_HASHFN);

  uint16_t hashes[4];
  hashes[0] = (h & 0xFFFF);
  hashes[1] = h >> 16 & 0xFFFF;
  hashes[2] = h >> 32 & 0xFFFF;
  hashes[3] = h >> 48 & 0xFFFF;

  _Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

  if (!cs) {
    bpf_printk("NULL CS!\n");
    return;
  }

  for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
    __u32 target_idx = hashes[i] & (COLUMNS - 1);

    // Check whether this is correct or not
    if (CHECK_BIT(hashes[i], 31)) {
      // Why am I not allowed to do this?
      /*
     __u32 (*ptr)[HASHFN_N][COLUMNS] = bpf_uptr_force_cast( cs->values, &arena, bpf_core_type_id_local(struct {__u32
   i[HASHFN_N][COLUMNS];})); bpf_printk("%llx\n", cs); bpf_printk("%u, %u\n", i, target_idx); bpf_printk("%llx\n", ptr);
   NO_TEAR_ADD((*ptr)[i][target_idx], 1);
      */
      // NO_TEAR_ADD(*((__u32*) cs + i * COLUMNS + target_idx ) , 1); //Does not work either
      __u32 *ptr = (__u32 *)bpf_uptr_force_cast(cs->values + i, &arena, bpf_core_type_id_local(struct { __u32 *i; }));
      __u32 *tmp = (__u32 *)bpf_uptr_force_cast(ptr + target_idx, &arena, bpf_core_type_id_local(struct { __u32 i; }));
      NO_TEAR_ADD(*tmp, 1);
    } else {
      // Why am I not allowed to do this?
      /*
      __u32 (*ptr)[HASHFN_N][COLUMNS] = bpf_uptr_force_cast( cs->values, &arena, bpf_core_type_id_local(struct {__u32
    i[HASHFN_N][COLUMNS];})); bpf_printk("%llx\n", cs); bpf_printk("%u, %u\n", i, target_idx); bpf_printk("%llx\n",
    ptr); NO_TEAR_ADD((*ptr)[i][target_idx], -1);
     */
      // NO_TEAR_ADD(*((__u32*) cs + i * COLUMNS + target_idx ) , -1); // Does not work either
      __u32 *ptr = (__u32 *)bpf_uptr_force_cast(cs->values + i, &arena, bpf_core_type_id_local(struct { __u32 *i; }));
      __u32 *tmp = (__u32 *)bpf_uptr_force_cast(ptr + target_idx, &arena, bpf_core_type_id_local(struct { __u32 i; }));
      NO_TEAR_ADD(*tmp, -1);
    }
  }
  return;
}

// add element and determine count
static void __always_inline countmin_add(struct countsketch *cs, void *element, __u64 len) {
  // Calculate just a single hash and re-use it to update and query the sketch
  uint64_t h = fasthash64(element, len, SEED_HASHFN);

  uint16_t hashes[4];
  hashes[0] = (h & 0xFFFF);
  hashes[1] = h >> 16 & 0xFFFF;
  hashes[2] = h >> 32 & 0xFFFF;
  hashes[3] = h >> 48 & 0xFFFF;

  _Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

  if (!cs) {
    bpf_printk("NULL CS!\n");
    return;
  }

  for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
    __u32 target_idx = hashes[i] & (COLUMNS - 1);
    __u32 *tmp = (__u32 *)bpf_uptr_cast((__u32 *)(cs->values + i) + target_idx, bpf_core_type_id_local(struct { __u32 i; }));
    NO_TEAR_ADD(*tmp, 1);
  }
  return;
}

#endif
