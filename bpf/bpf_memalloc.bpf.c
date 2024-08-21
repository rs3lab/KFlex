// SPDX-License-Identifier: GPL-2.0
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_experimental.bpf.h>
#include <bpf_helpers.bpf.h>
#include <bpf_memalloc.bpf.h>

struct foo {
  u64 data;
};

SEC("tc")
int prog(struct __sk_buff *ctx) {
  struct foo *f1 = emalloc(typeof(*f1));
  if (!f1 || f1->data != 69) {
    return TC_ACT_SHOT;
  }
  struct foo *f2 = emalloc(typeof(*f2));
  if (!f2 || f2->data != 69) {
    return TC_ACT_SHOT;
  }
  efree(f1);
  efree(f2);
  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
