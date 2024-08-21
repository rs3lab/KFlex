// SPDX-License-Identifier: GPL-2.0
#ifndef FFKX_BPF_FFKX_LLIST_BPF_H
#define FFKX_BPF_FFKX_LLIST_BPF_H
// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_helpers.h>
#include <ffkx_atomic.bpf.h>
#include <ffkx_helpers.bpf.h>

// Adaptation of the llist.h implementation from the Linux kernel.
/*
 * Lock-less NULL terminated single linked list
 *
 * Cases where locking is not needed:
 * If there are multiple producers and multiple consumers, llist_add can be used
 * in producers and llist_del_all can be used in consumers simultaneously
 * without locking. Also a single consumer can use llist_del_first while
 * multiple producers simultaneously use llist_add, without any locking.
 *
 * Cases where locking is needed:
 * If we have multiple consumers with llist_del_first used in one consumer, and
 * llist_del_first or llist_del_all used in other consumers, then a lock is
 * needed.  This is because llist_del_first depends on list->first->next not
 * changing, but without lock protection, there's no way to be sure about that
 * if a preemption happens in the middle of the delete operation and on being
 * preempted back, the list->first is the same as before causing the cmpxchg in
 * llist_del_first to succeed. For example, while a llist_del_first operation is
 * in progress in one consumer, then a llist_del_first, llist_add, llist_add (or
 * llist_del_all, llist_add, llist_add) sequence in another consumer may cause
 * violations.
 *
 * This can be summarized as follows:
 *
 *           |   add    | del_first |  del_all
 * add       |    -     |     -     |     -
 * del_first |          |     L     |     L
 * del_all   |          |           |     -
 *
 * Where, a particular row's operation can happen concurrently with a column's
 * operation, with "-" being no lock needed, while "L" being lock is needed.
 *
 * The list entries deleted via llist_del_all can be traversed with traversing
 * function such as llist_for_each etc.  But the list entries can not be
 * traversed safely before deleted from the list.  The order of deleted entries
 * is from the newest to the oldest added one.  If you want to traverse from the
 * oldest to the newest, you must reverse the order by yourself before
 * traversing.
 *
 * The basic atomic operation of this list is cmpxchg on long.  On architectures
 * that don't have NMI-safe cmpxchg implementation, the list can NOT be used in
 * NMI handlers.  So code that uses the list in an NMI handler should depend on
 * CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG.
 *
 * Copyright 2010,2011 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 */

struct ffkx_llist_head {
  struct ffkx_llist_node *first;
};

struct ffkx_llist_node {
  struct ffkx_llist_node *next;
};

#define FFKX_LLIST_HEAD_INIT(name) \
  { NULL }
#define FFKX_LLIST_HEAD(name) struct ffkx_llist_head name = FFKX_LLIST_HEAD_INIT(name)

/**
 * init_ffkx_llist_head - initialize lock-less list head
 * @head:	the head for your lock-less list
 */
static __always_inline void init_ffkx_llist_head(struct ffkx_llist_head *list) { list->first = NULL; }

/**
 * ffkx_llist_entry - get the struct of this entry
 * @ptr:	the &struct ffkx_llist_node pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the ffkx_llist_node within the struct.
 */
#define ffkx_llist_entry(ptr, type, member) ffkx_container_of(ptr, type, member)

/**
 * member_address_is_nonnull - check whether the member address is not NULL
 * @ptr:	the object pointer (struct type * that contains the ffkx_llist_node)
 * @member:	the name of the ffkx_llist_node within the struct.
 *
 * This macro is conceptually the same as
 *	&ptr->member != NULL
 * but it works around the fact that compilers can decide that taking a member
 * address is never a NULL pointer.
 *
 * Real objects that start at a high address and have a member at NULL are
 * unlikely to exist, but such pointers may be returned e.g. by the
 * container_of() macro.
 */
#define member_address_is_nonnull(ptr, member) ((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)

/**
 * ffkx_llist_for_each - iterate over some deleted entries of a lock-less list
 * @pos:	the &struct ffkx_llist_node to use as a loop cursor
 * @node:	the first entry of deleted list entries
 *
 * In general, some entries of the lock-less list can be traversed
 * safely only after being deleted from list, so start with an entry
 * instead of list head.
 *
 * If being used on entries deleted from lock-less list directly, the
 * traverse order is from the newest to the oldest added entry.  If
 * you want to traverse from the oldest to the newest, you must
 * reverse the order by yourself before traversing.
 */
#define ffkx_llist_for_each(pos, node) for ((pos) = (node); pos; (pos) = (pos)->next)

/**
 * ffkx_llist_for_each_safe - iterate over some deleted entries of a lock-less list
 *			 safe against removal of list entry
 * @pos:	the &struct ffkx_llist_node to use as a loop cursor
 * @n:		another &struct ffkx_llist_node to use as temporary storage
 * @node:	the first entry of deleted list entries
 *
 * In general, some entries of the lock-less list can be traversed
 * safely only after being deleted from list, so start with an entry
 * instead of list head.
 *
 * If being used on entries deleted from lock-less list directly, the
 * traverse order is from the newest to the oldest added entry.  If
 * you want to traverse from the oldest to the newest, you must
 * reverse the order by yourself before traversing.
 */
#define ffkx_llist_for_each_safe(pos, n, node) for ((pos) = (node); (pos) && ((n) = (pos)->next, true); (pos) = (n))

/**
 * ffkx_llist_for_each_entry - iterate over some deleted entries of lock-less list of given type
 * @pos:	the type * to use as a loop cursor.
 * @node:	the fist entry of deleted list entries.
 * @member:	the name of the ffkx_llist_node with the struct.
 *
 * In general, some entries of the lock-less list can be traversed
 * safely only after being removed from list, so start with an entry
 * instead of list head.
 *
 * If being used on entries deleted from lock-less list directly, the
 * traverse order is from the newest to the oldest added entry.  If
 * you want to traverse from the oldest to the newest, you must
 * reverse the order by yourself before traversing.
 */
#define ffkx_llist_for_each_entry(pos, node, member)                                                     \
  for ((pos) = ffkx_llist_entry((node), typeof(*(pos)), member); member_address_is_nonnull(pos, member); \
       (pos) = ffkx_llist_entry((pos)->member.next, typeof(*(pos)), member))

/**
 * ffkx_llist_for_each_entry_safe - iterate over some deleted entries of lock-less list of given type
 *			       safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @node:	the first entry of deleted list entries.
 * @member:	the name of the ffkx_llist_node with the struct.
 *
 * In general, some entries of the lock-less list can be traversed
 * safely only after being removed from list, so start with an entry
 * instead of list head.
 *
 * If being used on entries deleted from lock-less list directly, the
 * traverse order is from the newest to the oldest added entry.  If
 * you want to traverse from the oldest to the newest, you must
 * reverse the order by yourself before traversing.
 */
#define ffkx_llist_for_each_entry_safe(pos, n, node, member)                                                         \
  for (pos = ffkx_llist_entry((node), typeof(*pos), member);                                                         \
       member_address_is_nonnull(pos, member) && (n = ffkx_llist_entry(pos->member.next, typeof(*n), member), true); \
       pos = n)

/**
 * ffkx_llist_empty - tests whether a lock-less list is empty
 * @head:	the list to test
 *
 * Not guaranteed to be accurate or up to date.  Just a quick way to
 * test whether the list is empty without deleting something from the
 * list.
 */
static __always_inline bool ffkx_llist_empty(const struct ffkx_llist_head *head) {
  return FFKX_READ_ONCE(head->first) == NULL;
}

static __always_inline struct ffkx_llist_node *ffkx_llist_next(struct ffkx_llist_node *node) { return node->next; }

bool ffkx_llist_add_batch(struct ffkx_llist_node *new_first, struct ffkx_llist_node *new_last,
                         struct ffkx_llist_head *head);

static __always_inline bool __ffkx_llist_add_batch(struct ffkx_llist_node *new_first, struct ffkx_llist_node *new_last,
                                                  struct ffkx_llist_head *head) {
  new_last->next = head->first;
  head->first = new_first;
  return new_last->next == NULL;
}

/**
 * ffkx_llist_add - add a new entry
 * @new:	new entry to be added
 * @head:	the head for your lock-less list
 *
 * Returns true if the list was empty prior to adding this entry.
 */
static __always_inline bool ffkx_llist_add(struct ffkx_llist_node *new, struct ffkx_llist_head *head) {
  return ffkx_llist_add_batch(new, new, head);
}

static __always_inline bool __ffkx_llist_add(struct ffkx_llist_node *new, struct ffkx_llist_head *head) {
  return __ffkx_llist_add_batch(new, new, head);
}

/**
 * ffkx_llist_del_all - delete all entries from lock-less list
 * @head:	the head of lock-less list to delete all entries
 *
 * If list is empty, return NULL, otherwise, delete all entries and
 * return the pointer to the first entry.  The order of entries
 * deleted is from the newest to the oldest added one.
 */
static __always_inline struct ffkx_llist_node *ffkx_llist_del_all(struct ffkx_llist_head *head) {
  return ffkx_atomic_xchg(&head->first, NULL);
}

static __always_inline struct ffkx_llist_node *__ffkx_llist_del_all(struct ffkx_llist_head *head) {
  struct ffkx_llist_node *first = head->first;

  head->first = NULL;
  return first;
}

struct ffkx_llist_node *ffkx_llist_del_first(struct ffkx_llist_head *head);

struct ffkx_llist_node *ffkx_llist_reverse_order(struct ffkx_llist_node *head);

#endif
