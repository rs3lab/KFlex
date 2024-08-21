#pragma once
#define CS_ROWS 4
#define CS_COLUMNS 512

#define HASHFN_N CS_ROWS
#define COLUMNS CS_COLUMNS

#define SEED_HASHFN 0x2d31e867
#define COUNT_PACKETS
#define ACTION_DROP
#define COUNTMIN

#ifdef EKC_COUNTSKETCH_COMMON_USERSPACE
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;
#endif

struct countsketch {
  __u32 values[HASHFN_N][COLUMNS];
};

struct pkt_md {
#ifdef COUNT_PACKETS
  __u64 drop_cnt;
#endif
#ifdef COUNT_BYTES
  __u64 bytes_cnt;
#endif
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  __u8 proto;
} __attribute__((packed));
