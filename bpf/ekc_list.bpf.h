// SPDX-License-Identifier: GPL-2.0
#ifndef EKCACHE_BPF_EKC_LIST_BPF_H
#define EKCACHE_BPF_EKC_LIST_BPF_H

struct ekc_slist_head {
	struct ekc_slist_head *next;
};

struct ekc_list_head {
  struct ekc_list_head *next;
  struct ekc_list_head *prev;
};

#endif
