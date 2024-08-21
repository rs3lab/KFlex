// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_HELPERS_BPF_H
#define FFKX_BPF_FFKX_HELPERS_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_helpers.h>
#include <ffkx_heap.bpf.h>

extern const bool CONFIG_PREEMPT_NONE __kconfig;
extern const bool CONFIG_PREEMPT_VOLUNTARY __kconfig;

void bpf_preempt_disable(void) __ksym;
void bpf_preempt_enable(void) __ksym;

// Only emit the call to the kfuncs if we are on a config where disabled
// preemption is not guranteed already.
static __always_inline void ffkx_preempt_disable(void) {
  if (!CONFIG_PREEMPT_NONE && !CONFIG_PREEMPT_VOLUNTARY) {
    bpf_preempt_disable();
  }
}

static __always_inline void ffkx_preempt_enable(void) {
  if (!CONFIG_PREEMPT_NONE && !CONFIG_PREEMPT_VOLUNTARY) {
    bpf_preempt_enable();
  }
}

#endif
