// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_helpers.h>
#include <ekc_atomic.bpf.h>
#include <ekc_helpers.bpf.h>
#include <ekc_spin_lock.bpf.h>

struct ekc_lock_node ekc_cpu_lock_nodes[1] SEC(".data.ekc_per_cpu_lock_nodes");

__hidden void ekc_spin_lock_slowpath(struct ekc_lock_node *pred, struct ekc_lock_node *node) {
  node->locked = true;
  EKC_WRITE_ONCE(pred->next, node);
  bpf_repeat(BPF_MAX_LOOPS) {
    if (!EKC_READ_ONCE(node->locked)) {
      break;
    }
  }
}
