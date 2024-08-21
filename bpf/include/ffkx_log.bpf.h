// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_LOG_BPF_H
#define FFKX_BPF_FFKX_LOG_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on

enum ffkx_log_level {
  FFKX_LOG_LEVEL_NONE,
  FFKX_LOG_LEVEL_ERROR,
  FFKX_LOG_LEVEL_INFO,
  FFKX_LOG_LEVEL_DEBUG,
};

const volatile int ffkx_log_level = FFKX_LOG_LEVEL_ERROR;

#define FFKX_LOG_DISABLE

#ifdef FFKX_LOG_DISABLE
#define __ffkx_log(...)
#else
#define __ffkx_log(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#endif

#define ffkx_log_error(fmt, ...) __ffkx_log("[E]: %s: " fmt, __func__, ##__VA_ARGS__)
#define ffkx_log_info(fmt, ...) __ffkx_log("[I]: %s: " fmt, __func__, ##__VA_ARGS__)
#define ffkx_log_debug(...)
//#define ffkx_log_debug(fmt, ...) __ffkx_log("[D]: %s: " fmt, __func__, ##__VA_ARGS__)

#define ffkx_pkt_log_error(pkt, fmt, ...) ffkx_log_error("(pkt=0x%llx) " fmt, (long long)pkt, ##__VA_ARGS__)
#define ffkx_pkt_log_info(pkt, fmt, ...) ffkx_log_info("(pkt=0x%llx) " fmt, (long long)pkt, ##__VA_ARGS__)
#define ffkx_pkt_log_debug(...)
//#define ffkx_pkt_log_debug(pkt, fmt, ...) ffkx_log_debug("(pkt=0x%llx) " fmt, (long long)pkt, ##__VA_ARGS__)

#endif
