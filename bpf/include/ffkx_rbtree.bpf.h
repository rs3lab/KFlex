// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef FFKX_BPF_FFKX_RBTREE_BPF_H
#define FFKX_BPF_FFKX_RBTREE_BPF_H

// clang-format off
#include <vmlinux.h>
// clang-format on
#include <bpf_helpers.h>
#include <ffkx_atomic.bpf.h>
#include <ffkx_heap.bpf.h>
#include <ffkx_util.bpf.h>

struct ffkx_rb_node {
  struct ffkx_rb_node *__rb_parent_color;
  struct ffkx_rb_node *rb_right;
  struct ffkx_rb_node *rb_left;
};

struct ffkx_rb_root {
  struct ffkx_rb_node *rb_node;
};

struct ffkx_rb_root_cached {
  struct ffkx_rb_root rb_root;
  struct ffkx_rb_node *rb_leftmost;
};

/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  (C) 2002  David Woodhouse <dwmw2@infradead.org>
  (C) 2012  Michel Lespinasse <walken@google.com>


  linux/lib/rbtree.c
*/

/*
 * red-black trees properties:  https://en.wikipedia.org/wiki/Rbtree
 *
 *  1) A node is either red or black
 *  2) The root is black
 *  3) All leaves (NULL) are black
 *  4) Both children of every red node are black
 *  5) Every simple path from root to leaves contains the same number
 *     of black nodes.
 *
 *  4 and 5 give the O(log n) guarantee, since 4 implies you cannot have two
 *  consecutive red nodes in a path and every red node is therefore followed by
 *  a black. So if B is the number of black nodes on every simple path (as per
 *  5), then the longest possible path due to 4 is 2B.
 *
 *  We shall indicate color with case, where black nodes are uppercase and red
 *  nodes will be lowercase. Unknown color nodes shall be drawn as red within
 *  parentheses and have some accompanying text comment.
 */

/*
 * Notes on lockless lookups:
 *
 * All stores to the tree structure (rb_left and rb_right) must be done using
 * FFKX_WRITE_ONCE(). And we must not inadvertently cause (temporary) loops in the
 * tree structure as seen in program order.
 *
 * These two requirements will allow lockless iteration of the tree -- not
 * correct iteration mind you, tree rotations are not atomic so a lookup might
 * miss entire subtrees.
 *
 * But they do guarantee that any such traversal will only see valid elements
 * and that it will indeed complete -- does not get stuck in a loop.
 *
 * It also guarantees that if the lookup returns an element it is the 'correct'
 * one. But not returning an element does _NOT_ mean it's not present.
 *
 * NOTE:
 *
 * Stores to __rb_parent_color are not important for simple lookups so those
 * are left undone as of now. Nor did I check for loops involving parent
 * pointers.
 */

#define RB_ROOT \
  (struct ffkx_rb_root) { NULL, }
#define RB_ROOT_CACHED           \
  (struct ffkx_rb_root_cached) { \
    {                            \
        NULL,                    \
    },                           \
        NULL                     \
  }

// We have to do a reinterpret_cast, to preserve NULL-ness, as c may not be
// non-NULL always.
#define __rb_parent(c)                                       \
  ({                                                         \
    auto __r = (struct ffkx_rb_node *)(scalar_cast(c) & ~3); \
    reinterpret_cast(typeof(*__r), __r);                     \
    __r;                                                     \
  })

#define rb_parent(r) __rb_parent((u64)((r)->__rb_parent_color))

#define rb_entry(ptr, type, member) ffkx_container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root) (FFKX_READ_ONCE((root)->rb_node) == NULL)

/* 'empty' nodes are nodes that are known not to be inserted in an rbtree */
#define RB_EMPTY_NODE(node) ((node)->__rb_parent_color == (node))
#define RB_CLEAR_NODE(node) ((node)->__rb_parent_color = (node))

#define RB_RED 0
#define RB_BLACK 1

#define __rb_color(pc) (scalar_cast(pc) & 1)
#define __rb_is_black(pc) __rb_color(pc)
#define __rb_is_red(pc) (!__rb_color(pc))
#define rb_color(rb) __rb_color((rb)->__rb_parent_color)
#define rb_is_red(rb) __rb_is_red((rb)->__rb_parent_color)
#define rb_is_black(rb) __rb_is_black((rb)->__rb_parent_color)

// FIXME: DOcumentation on our changes to __rb_parent_color
// To ensure translation, we made __rb_parent_color a pointer.
// This means all usage needs to be updated that was assuming that it was an
// unsigned long, such that adding 1 now yields a different value. We have done
// that, but let's document this in detail later.

static inline void rb_set_parent(struct ffkx_rb_node *rb, struct ffkx_rb_node *p) {
  // We don't need to be careful here, as pointer translation affects upper
  // bits.
  rb->__rb_parent_color = (struct ffkx_rb_node *)(rb_color(rb) + (u64)p);
}

static inline void rb_set_parent_color(struct ffkx_rb_node *rb, struct ffkx_rb_node *p, int color) {
  // Likewise
  rb->__rb_parent_color = (struct ffkx_rb_node *)((u64)p + color);
}

static inline void __rb_change_child(struct ffkx_rb_node *old, struct ffkx_rb_node *new, struct ffkx_rb_node *parent,
                                     struct ffkx_rb_root *root) {
  if (parent) {
    if (parent->rb_left == old)
      FFKX_WRITE_ONCE(parent->rb_left, new);
    else
      FFKX_WRITE_ONCE(parent->rb_right, new);
  } else
    FFKX_WRITE_ONCE(root->rb_node, new);
}

static inline void __rb_change_child_rcu(struct ffkx_rb_node *old, struct ffkx_rb_node *new,
                                         struct ffkx_rb_node *parent, struct ffkx_rb_root *root) {
  if (parent) {
    if (parent->rb_left == old)
      rcu_assign_pointer(parent->rb_left, new);
    else
      rcu_assign_pointer(parent->rb_right, new);
  } else
    rcu_assign_pointer(root->rb_node, new);
}

static inline void rb_link_node(struct ffkx_rb_node *node, struct ffkx_rb_node *parent, struct ffkx_rb_node **rb_link) {
  node->__rb_parent_color = parent;
  node->rb_left = node->rb_right = NULL;

  *rb_link = node;
}

static inline void rb_link_node_rcu(struct ffkx_rb_node *node, struct ffkx_rb_node *parent,
                                    struct ffkx_rb_node **rb_link) {
  node->__rb_parent_color = parent;
  node->rb_left = node->rb_right = NULL;

  rcu_assign_pointer(*rb_link, node);
}

#define rb_entry_safe(ptr, type, member)              \
  ({                                                  \
    typeof(ptr) ____ptr = (ptr);                      \
    ____ptr ? rb_entry(____ptr, type, member) : NULL; \
  })

/**
 * rbtree_postorder_for_each_entry_safe - iterate in post-order over rb_root of
 * given type allowing the backing memory of @pos to be invalidated
 *
 * @pos:	the 'type *' to use as a loop cursor.
 * @n:		another 'type *' to use as temporary storage
 * @root:	'rb_root *' of the rbtree.
 * @field:	the name of the rb_node field within 'type'.
 *
 * rbtree_postorder_for_each_entry_safe() provides a similar guarantee as
 * list_for_each_entry_safe() and allows the iteration to continue independent
 * of changes to @pos by the body of the loop.
 *
 * Note, however, that it cannot handle other modifications that re-order the
 * rbtree it is iterating over. This includes calling rb_erase() on @pos, as
 * rb_erase() may rebalance the tree, causing us to miss some nodes.
 */
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field)                    \
  ffkx_for(pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field);       \
           ffkx_cond && pos && ({                                                    \
             n = rb_entry_safe(rb_next_postorder(&pos->field), typeof(*pos), field); \
             1;                                                                      \
           });                                                                       \
           pos = n)

/* Same as rb_first(), but O(1) */
#define rb_first_cached(root) (root)->rb_leftmost

static inline void rb_set_black(struct ffkx_rb_node *rb) {
  rb->__rb_parent_color = (struct ffkx_rb_node *)((u64)rb->__rb_parent_color + RB_BLACK);
}

static inline struct ffkx_rb_node *rb_red_parent(struct ffkx_rb_node *red) { return red->__rb_parent_color; }

/*
 * Helper function for rotations:
 * - old's parent and color get assigned to new
 * - old gets assigned new as a parent and 'color' as a color.
 */
static inline void __rb_rotate_set_parents(struct ffkx_rb_node *old, struct ffkx_rb_node *new,
                                           struct ffkx_rb_root *root, int color) {
  struct ffkx_rb_node *parent = rb_parent(old);
  new->__rb_parent_color = old->__rb_parent_color;
  rb_set_parent_color(old, new, color);
  __rb_change_child(old, new, parent, root);
}

static __always_inline void __rb_insert(struct ffkx_rb_node *node, struct ffkx_rb_root *root) {
  struct ffkx_rb_node *parent = rb_red_parent(node), *gparent, *tmp;

  ffkx_while(true) {
    /*
     * Loop invariant: node is red.
     */
    if (!parent) {
      /*
       * The inserted node is root. Either this is the
       * first node, or we recursed at Case 1 below and
       * are no longer violating 4).
       */
      rb_set_parent_color(node, NULL, RB_BLACK);
      break;
    }

    /*
     * If there is a black parent, we are done.
     * Otherwise, take some corrective action as,
     * per 4), we don't want a red root or two
     * consecutive red nodes.
     */
    if (rb_is_black(parent)) break;

    gparent = rb_red_parent(parent);

    tmp = gparent->rb_right;
    if (parent != tmp) { /* parent == gparent->rb_left */
      if (tmp && rb_is_red(tmp)) {
        /*
         * Case 1 - node's uncle is red (color flips).
         *
         *       G            g
         *      / \          / \
         *     p   u  -->   P   U
         *    /            /
         *   n            n
         *
         * However, since g's parent might be red, and
         * 4) does not allow this, we need to recurse
         * at g.
         */
        rb_set_parent_color(tmp, gparent, RB_BLACK);
        rb_set_parent_color(parent, gparent, RB_BLACK);
        node = gparent;
        parent = rb_parent(node);
        rb_set_parent_color(node, parent, RB_RED);
        continue;
      }

      tmp = parent->rb_right;
      if (node == tmp) {
        /*
         * Case 2 - node's uncle is black and node is
         * the parent's right child (left rotate at parent).
         *
         *      G             G
         *     / \           / \
         *    p   U  -->    n   U
         *     \           /
         *      n         p
         *
         * This still leaves us in violation of 4), the
         * continuation into Case 3 will fix that.
         */
        tmp = node->rb_left;
        FFKX_WRITE_ONCE(parent->rb_right, tmp);
        FFKX_WRITE_ONCE(node->rb_left, parent);
        if (tmp) rb_set_parent_color(tmp, parent, RB_BLACK);
        rb_set_parent_color(parent, node, RB_RED);
        parent = node;
        tmp = node->rb_right;
      }

      /*
       * Case 3 - node's uncle is black and node is
       * the parent's left child (right rotate at gparent).
       *
       *        G           P
       *       / \         / \
       *      p   U  -->  n   g
       *     /                 \
       *    n                   U
       */
      FFKX_WRITE_ONCE(gparent->rb_left, tmp); /* == parent->rb_right */
      FFKX_WRITE_ONCE(parent->rb_right, gparent);
      if (tmp) rb_set_parent_color(tmp, gparent, RB_BLACK);
      __rb_rotate_set_parents(gparent, parent, root, RB_RED);
      break;
    } else {
      tmp = gparent->rb_left;
      if (tmp && rb_is_red(tmp)) {
        /* Case 1 - color flips */
        rb_set_parent_color(tmp, gparent, RB_BLACK);
        rb_set_parent_color(parent, gparent, RB_BLACK);
        node = gparent;
        parent = rb_parent(node);
        rb_set_parent_color(node, parent, RB_RED);
        continue;
      }

      tmp = parent->rb_left;
      if (node == tmp) {
        /* Case 2 - right rotate at parent */
        tmp = node->rb_right;
        FFKX_WRITE_ONCE(parent->rb_left, tmp);
        FFKX_WRITE_ONCE(node->rb_right, parent);
        if (tmp) rb_set_parent_color(tmp, parent, RB_BLACK);
        rb_set_parent_color(parent, node, RB_RED);
        parent = node;
        tmp = node->rb_left;
      }

      /* Case 3 - left rotate at gparent */
      FFKX_WRITE_ONCE(gparent->rb_right, tmp); /* == parent->rb_left */
      FFKX_WRITE_ONCE(parent->rb_left, gparent);
      if (tmp) rb_set_parent_color(tmp, gparent, RB_BLACK);
      __rb_rotate_set_parents(gparent, parent, root, RB_RED);
      break;
    }
  }
}

/*
 * Inline version for rb_erase() use - we want to be able to inline
 * and eliminate the dummy_rotate callback there
 */
static __always_inline void ____rb_erase_color(struct ffkx_rb_node *parent, struct ffkx_rb_root *root) {
  struct ffkx_rb_node *node = NULL, *sibling, *tmp1, *tmp2;

  ffkx_while(true) {
    /*
     * Loop invariants:
     * - node is black (or NULL on first iteration)
     * - node is not the root (parent is not NULL)
     * - All leaf paths going through parent and node have a
     *   black node count that is 1 lower than other leaf paths.
     */
    sibling = parent->rb_right;
    if (node != sibling) { /* node == parent->rb_left */
      if (rb_is_red(sibling)) {
        /*
         * Case 1 - left rotate at parent
         *
         *     P               S
         *    / \             / \
         *   N   s    -->    p   Sr
         *      / \         / \
         *     Sl  Sr      N   Sl
         */
        tmp1 = sibling->rb_left;
        FFKX_WRITE_ONCE(parent->rb_right, tmp1);
        FFKX_WRITE_ONCE(sibling->rb_left, parent);
        rb_set_parent_color(tmp1, parent, RB_BLACK);
        __rb_rotate_set_parents(parent, sibling, root, RB_RED);
        sibling = tmp1;
      }
      tmp1 = sibling->rb_right;
      if (!tmp1 || rb_is_black(tmp1)) {
        tmp2 = sibling->rb_left;
        if (!tmp2 || rb_is_black(tmp2)) {
          /*
           * Case 2 - sibling color flip
           * (p could be either color here)
           *
           *    (p)           (p)
           *    / \           / \
           *   N   S    -->  N   s
           *      / \           / \
           *     Sl  Sr        Sl  Sr
           *
           * This leaves us violating 5) which
           * can be fixed by flipping p to black
           * if it was red, or by recursing at p.
           * p is red when coming from Case 1.
           */
          rb_set_parent_color(sibling, parent, RB_RED);
          if (rb_is_red(parent))
            rb_set_black(parent);
          else {
            node = parent;
            parent = rb_parent(node);
            if (parent) continue;
          }
          break;
        }
        /*
         * Case 3 - right rotate at sibling
         * (p could be either color here)
         *
         *   (p)           (p)
         *   / \           / \
         *  N   S    -->  N   sl
         *     / \             \
         *    sl  Sr            S
         *                       \
         *                        Sr
         *
         * Note: p might be red, and then both
         * p and sl are red after rotation(which
         * breaks property 4). This is fixed in
         * Case 4 (in __rb_rotate_set_parents()
         *         which set sl the color of p
         *         and set p RB_BLACK)
         *
         *   (p)            (sl)
         *   / \            /  \
         *  N   sl   -->   P    S
         *       \        /      \
         *        S      N        Sr
         *         \
         *          Sr
         */
        tmp1 = tmp2->rb_right;
        FFKX_WRITE_ONCE(sibling->rb_left, tmp1);
        FFKX_WRITE_ONCE(tmp2->rb_right, sibling);
        FFKX_WRITE_ONCE(parent->rb_right, tmp2);
        if (tmp1) rb_set_parent_color(tmp1, sibling, RB_BLACK);
        tmp1 = sibling;
        sibling = tmp2;
      }
      /*
       * Case 4 - left rotate at parent + color flips
       * (p and sl could be either color here.
       *  After rotation, p becomes black, s acquires
       *  p's color, and sl keeps its color)
       *
       *      (p)             (s)
       *      / \             / \
       *     N   S     -->   P   Sr
       *        / \         / \
       *      (sl) sr      N  (sl)
       */
      tmp2 = sibling->rb_left;
      FFKX_WRITE_ONCE(parent->rb_right, tmp2);
      FFKX_WRITE_ONCE(sibling->rb_left, parent);
      rb_set_parent_color(tmp1, sibling, RB_BLACK);
      if (tmp2) rb_set_parent(tmp2, parent);
      __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
      break;
    } else {
      sibling = parent->rb_left;
      if (rb_is_red(sibling)) {
        /* Case 1 - right rotate at parent */
        tmp1 = sibling->rb_right;
        FFKX_WRITE_ONCE(parent->rb_left, tmp1);
        FFKX_WRITE_ONCE(sibling->rb_right, parent);
        rb_set_parent_color(tmp1, parent, RB_BLACK);
        __rb_rotate_set_parents(parent, sibling, root, RB_RED);
        sibling = tmp1;
      }
      tmp1 = sibling->rb_left;
      if (!tmp1 || rb_is_black(tmp1)) {
        tmp2 = sibling->rb_right;
        if (!tmp2 || rb_is_black(tmp2)) {
          /* Case 2 - sibling color flip */
          rb_set_parent_color(sibling, parent, RB_RED);
          if (rb_is_red(parent))
            rb_set_black(parent);
          else {
            node = parent;
            parent = rb_parent(node);
            if (parent) continue;
          }
          break;
        }
        /* Case 3 - left rotate at sibling */
        tmp1 = tmp2->rb_left;
        FFKX_WRITE_ONCE(sibling->rb_right, tmp1);
        FFKX_WRITE_ONCE(tmp2->rb_left, sibling);
        FFKX_WRITE_ONCE(parent->rb_left, tmp2);
        if (tmp1) rb_set_parent_color(tmp1, sibling, RB_BLACK);
        tmp1 = sibling;
        sibling = tmp2;
      }
      /* Case 4 - right rotate at parent + color flips */
      tmp2 = sibling->rb_right;
      FFKX_WRITE_ONCE(parent->rb_left, tmp2);
      FFKX_WRITE_ONCE(sibling->rb_right, parent);
      rb_set_parent_color(tmp1, sibling, RB_BLACK);
      if (tmp2) rb_set_parent(tmp2, parent);
      __rb_rotate_set_parents(parent, sibling, root, RB_BLACK);
      break;
    }
  }
}

/* Non-inline version for rb_erase_augmented() use */
static void __rb_erase_color(struct ffkx_rb_node *parent, struct ffkx_rb_root *root) {
  ____rb_erase_color(parent, root);
}

/*
 * Non-augmented rbtree manipulation functions.
 *
 * We use dummy augmented callbacks here, and have the compiler optimize them
 * out of the rb_insert_color() and rb_erase() function definitions.
 */

static inline void rb_insert_color(struct ffkx_rb_node *node, struct ffkx_rb_root *root) { __rb_insert(node, root); }

// We don't use augmented callbacks, hence removed.
static __always_inline struct ffkx_rb_node *__rb_erase_augmented(struct ffkx_rb_node *node, struct ffkx_rb_root *root) {
  struct ffkx_rb_node *child = node->rb_right;
  struct ffkx_rb_node *tmp = node->rb_left;
  struct ffkx_rb_node *parent, *rebalance;
  struct ffkx_rb_node *pc;

  if (!tmp) {
    /*
     * Case 1: node to erase has no more than 1 child (easy!)
     *
     * Note that if there is one child it must be red due to 5)
     * and node must be black due to 4). We adjust colors locally
     * so as to bypass __rb_erase_color() later on.
     */
    pc = node->__rb_parent_color;
    parent = __rb_parent(pc);
    __rb_change_child(node, child, parent, root);
    if (child) {
      child->__rb_parent_color = pc;
      rebalance = NULL;
    } else
      rebalance = __rb_is_black(pc) ? parent : NULL;
    tmp = parent;
  } else if (!child) {
    /* Still case 1, but this time the child is node->rb_left */
    tmp->__rb_parent_color = pc = node->__rb_parent_color;
    parent = __rb_parent(pc);
    __rb_change_child(node, tmp, parent, root);
    rebalance = NULL;
    tmp = parent;
  } else {
    struct ffkx_rb_node *successor = child, *child2;

    tmp = child->rb_left;
    if (!tmp) {
      /*
       * Case 2: node's successor is its right child
       *
       *    (n)          (s)
       *    / \          / \
       *  (x) (s)  ->  (x) (c)
       *        \
       *        (c)
       */
      parent = successor;
      child2 = successor->rb_right;
    } else {
      /*
       * Case 3: node's successor is leftmost under
       * node's right child subtree
       *
       *    (n)          (s)
       *    / \          / \
       *  (x) (y)  ->  (x) (y)
       *      /            /
       *    (p)          (p)
       *    /            /
       *  (s)          (c)
       *    \
       *    (c)
       */
      // FIXME: How can we express do {} while () in ffkx_loop
      //      do {
      //        parent = successor;
      //        successor = tmp;
      //        tmp = tmp->rb_left;
      //      } while (tmp);
      {  // do
        parent = successor;
        successor = tmp;
        tmp = tmp->rb_left;
        ffkx_while(tmp) {
          parent = successor;
          successor = tmp;
          tmp = tmp->rb_left;
        }
      }
      child2 = successor->rb_right;
      FFKX_WRITE_ONCE(parent->rb_left, child2);
      FFKX_WRITE_ONCE(successor->rb_right, child);
      rb_set_parent(child, successor);
    }

    tmp = node->rb_left;
    FFKX_WRITE_ONCE(successor->rb_left, tmp);
    rb_set_parent(tmp, successor);

    pc = node->__rb_parent_color;
    tmp = __rb_parent(pc);
    __rb_change_child(node, successor, tmp, root);

    if (child2) {
      rb_set_parent_color(child2, parent, RB_BLACK);
      rebalance = NULL;
    } else {
      // FIXME: The compiler does bit arithmetic on the pointer to somehow avoid
      // doing separate stores and a jump for the following sequence.
      // rebalance = rb_is_black(succesor) ? parent : NULL
      // ; if (rb_is_black(successor)) @ ffkx_rbtree.bpf.h:603 289: (79) r1 = *(u64 *)(r10 -40)      ;
      // R1_w=ptr_rb_node() R10=fp0 fp-40=ptr_rb_node()
      // 290: (79) r1 = *(u64 *)(r1 +0)        ; R1_w=scalar()
      // 291: (85) call bpf_scalar_cast#40994          ; R0_w=scalar()
      // 292: (79) r1 = *(u64 *)(r10 -40)      ; R1_w=ptr_rb_node() R10=fp0 fp-40=ptr_rb_node()
      // 293: (bf) r8 = r0                     ; R0_w=scalar(id=46) R8_w=scalar(id=46)
      // 294: (57) r8 &= 1                     ; R8_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=1,var_off=(0x0; 0x1))
      // 295: (87) r8 = -r8                    ; R8_w=scalar()
      // 296: (79) r2 = *(u64 *)(r10 -16)      ; R2_w=ptr_rb_node() R10=fp0 fp-16=ptr_rb_node()
      // 297: (5f) r8 &= r2
      // Let us use barrier_var to avoid this, but remember to fix such
      // arithmetic on pointers later.
      // TODO(kkd): Allow bit operations on pointers, but mark them untrusted.

      bool is_black = rb_is_black(successor);
      // Make the compiler forget about this value.
      barrier_var(is_black);
      rebalance = is_black ? parent : NULL;
    }
    successor->__rb_parent_color = pc;
    tmp = successor;
  }

  return rebalance;
}

static void rb_erase(struct ffkx_rb_node *node, struct ffkx_rb_root *root) {
  struct ffkx_rb_node *rebalance;
  rebalance = __rb_erase_augmented(node, root);
  if (rebalance) ____rb_erase_color(rebalance, root);
}

/*
 * This function returns the first node (in sort order) of the tree.
 */
static struct ffkx_rb_node *rb_first(const struct ffkx_rb_root *root) {
  struct ffkx_rb_node *n;

  n = root->rb_node;
  if (!n) return NULL;
  ffkx_while(n->rb_left) n = n->rb_left;
  return n;
}

static struct ffkx_rb_node *rb_last(const struct ffkx_rb_root *root) {
  struct ffkx_rb_node *n;

  n = root->rb_node;
  if (!n) return NULL;
  ffkx_while(n->rb_right) n = n->rb_right;
  return n;
}

static struct ffkx_rb_node *rb_next(const struct ffkx_rb_node *node) {
  struct ffkx_rb_node *parent;

  if (RB_EMPTY_NODE(node)) return NULL;

  /*
   * If we have a right-hand child, go down and then left as far
   * as we can.
   */
  if (node->rb_right) {
    node = node->rb_right;
    ffkx_while(node->rb_left) node = node->rb_left;
    return (struct ffkx_rb_node *)node;
  }

  /*
   * No right-hand children. Everything down and left is smaller than us,
   * so any 'next' node must be in the general direction of our parent.
   * Go up the tree; any time the ancestor is a right-hand child of its
   * parent, keep going up. First time it's a left-hand child of its
   * parent, said parent is our 'next' node.
   */
  ffkx_while((parent = rb_parent(node)) && node == parent->rb_right) node = parent;

  return parent;
}

static struct ffkx_rb_node *rb_prev(const struct ffkx_rb_node *node) {
  struct ffkx_rb_node *parent;

  if (RB_EMPTY_NODE(node)) return NULL;

  /*
   * If we have a left-hand child, go down and then right as far
   * as we can.
   */
  if (node->rb_left) {
    node = node->rb_left;
    ffkx_while(node->rb_right) node = node->rb_right;
    return (struct ffkx_rb_node *)node;
  }

  /*
   * No left-hand children. Go up till we find an ancestor which
   * is a right-hand child of its parent.
   */
  ffkx_while((parent = rb_parent(node)) && node == parent->rb_left) node = parent;

  return parent;
}

static void rb_replace_node(struct ffkx_rb_node *victim, struct ffkx_rb_node *new, struct ffkx_rb_root *root) {
  struct ffkx_rb_node *parent = rb_parent(victim);

  /* Copy the pointers/colour from the victim to the replacement */
  *new = *victim;

  /* Set the surrounding nodes to point to the replacement */
  if (victim->rb_left) rb_set_parent(victim->rb_left, new);
  if (victim->rb_right) rb_set_parent(victim->rb_right, new);
  __rb_change_child(victim, new, parent, root);
}

static void rb_replace_node_rcu(struct ffkx_rb_node *victim, struct ffkx_rb_node *new, struct ffkx_rb_root *root) {
  struct ffkx_rb_node *parent = rb_parent(victim);

  /* Copy the pointers/colour from the victim to the replacement */
  *new = *victim;

  /* Set the surrounding nodes to point to the replacement */
  if (victim->rb_left) rb_set_parent(victim->rb_left, new);
  if (victim->rb_right) rb_set_parent(victim->rb_right, new);

  /* Set the parent's pointer to the new node last after an RCU barrier
   * so that the pointers onwards are seen to be set correctly when doing
   * an RCU walk over the tree.
   */
  __rb_change_child_rcu(victim, new, parent, root);
}

static struct ffkx_rb_node *rb_left_deepest_node(const struct ffkx_rb_node *node) {
  ffkx_for(; ffkx_cond;) {
    if (node->rb_left)
      node = node->rb_left;
    else if (node->rb_right)
      node = node->rb_right;
    else
      break;
  }
  return (struct ffkx_rb_node *)node;
}

static struct ffkx_rb_node *rb_next_postorder(const struct ffkx_rb_node *node) {
  const struct ffkx_rb_node *parent;
  if (!node) return NULL;
  parent = rb_parent(node);

  /* If we're sitting on node, we've already seen our children */
  if (parent && node == parent->rb_left && parent->rb_right) {
    /* If we are the parent's left node, go to the parent's right
     * node then all the way down to the left */
    return rb_left_deepest_node(parent->rb_right);
  } else
    /* Otherwise we are the parent's right node, and the parent
     * should be next */
    return (struct ffkx_rb_node *)parent;
}

static struct ffkx_rb_node *rb_first_postorder(const struct ffkx_rb_root *root) {
  if (!root->rb_node) return NULL;

  return rb_left_deepest_node(root->rb_node);
}

static inline void rb_insert_color_cached(struct ffkx_rb_node *node, struct ffkx_rb_root_cached *root, bool leftmost) {
  if (leftmost) root->rb_leftmost = node;
  rb_insert_color(node, &root->rb_root);
}

static inline struct ffkx_rb_node *rb_erase_cached(struct ffkx_rb_node *node, struct ffkx_rb_root_cached *root) {
  struct ffkx_rb_node *leftmost = NULL;

  if (root->rb_leftmost == node) leftmost = root->rb_leftmost = rb_next(node);

  rb_erase(node, &root->rb_root);

  return leftmost;
}

static inline void rb_replace_node_cached(struct ffkx_rb_node *victim, struct ffkx_rb_node *new,
                                          struct ffkx_rb_root_cached *root) {
  if (root->rb_leftmost == victim) root->rb_leftmost = new;
  rb_replace_node(victim, new, &root->rb_root);
}

/*
 * The below helper functions use 2 operators with 3 different
 * calling conventions. The operators are related like:
 *
 *	comp(a->key,b) < 0  := less(a,b)
 *	comp(a->key,b) > 0  := less(b,a)
 *	comp(a->key,b) == 0 := !less(a,b) && !less(b,a)
 *
 * If these operators define a partial order on the elements we make no
 * guarantee on which of the elements matching the key is found. See
 * rb_find().
 *
 * The reason for this is to allow the find() interface without requiring an
 * on-stack dummy object, which might not be feasible due to object size.
 */

/**
 * rb_add_cached() - insert @node into the leftmost cached tree @tree
 * @node: node to insert
 * @tree: leftmost cached tree to insert @node into
 * @less: operator defining the (partial) node order
 *
 * Returns @node when it is the new leftmost, or NULL.
 */
static __always_inline struct ffkx_rb_node *rb_add_cached(struct ffkx_rb_node *node, struct ffkx_rb_root_cached *tree,
                                                          bool (*less)(struct ffkx_rb_node *,
                                                                       const struct ffkx_rb_node *)) {
  struct ffkx_rb_node **link = &tree->rb_root.rb_node;
  struct ffkx_rb_node *parent = NULL;
  bool leftmost = true;

  ffkx_for(; *link && ffkx_cond;) {
    parent = *link;
    if (less(node, parent)) {
      link = &parent->rb_left;
    } else {
      link = &parent->rb_right;
      leftmost = false;
    }
  }

  rb_link_node(node, parent, link);
  rb_insert_color_cached(node, tree, leftmost);

  return leftmost ? node : NULL;
}

/**
 * rb_add() - insert @node into @tree
 * @node: node to insert
 * @tree: tree to insert @node into
 * @less: operator defining the (partial) node order
 */
static __always_inline void rb_add(struct ffkx_rb_node *node, struct ffkx_rb_root *tree,
                                   bool (*less)(struct ffkx_rb_node *, const struct ffkx_rb_node *)) {
  struct ffkx_rb_node **link = &tree->rb_node;
  struct ffkx_rb_node *parent = NULL;

  ffkx_for(; *link && ffkx_cond;) {
    parent = *link;
    if (less(node, parent))
      link = &parent->rb_left;
    else
      link = &parent->rb_right;
  }

  rb_link_node(node, parent, link);
  rb_insert_color(node, tree);
}

/**
 * rb_find_add() - find equivalent @node in @tree, or add @node
 * @node: node to look-for / insert
 * @tree: tree to search / modify
 * @cmp: operator defining the node order
 *
 * Returns the rb_node matching @node, or NULL when no match is found and @node
 * is inserted.
 */
static __always_inline struct ffkx_rb_node *rb_find_add(struct ffkx_rb_node *node, struct ffkx_rb_root *tree,
                                                        int (*cmp)(struct ffkx_rb_node *,
                                                                   const struct ffkx_rb_node *)) {
  struct ffkx_rb_node **link = &tree->rb_node;
  struct ffkx_rb_node *parent = NULL;
  int c;

  ffkx_for(; *link && ffkx_cond;) {
    parent = *link;
    c = cmp(node, parent);

    if (c < 0)
      link = &parent->rb_left;
    else if (c > 0)
      link = &parent->rb_right;
    else
      return parent;
  }

  rb_link_node(node, parent, link);
  rb_insert_color(node, tree);
  return NULL;
}

/**
 * rb_find() - find @key in tree @tree
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining the node order
 *
 * Returns the rb_node matching @key or NULL.
 */
static __always_inline struct ffkx_rb_node *rb_find(const void *key, const struct ffkx_rb_root *tree,
                                                    int (*cmp)(const void *key, const struct ffkx_rb_node *)) {
  struct ffkx_rb_node *node = tree->rb_node;

  ffkx_while(node) {
    int c = cmp(key, node);

    if (c < 0)
      node = node->rb_left;
    else if (c > 0)
      node = node->rb_right;
    else
      return node;
  }

  return NULL;
}

/**
 * rb_find_first() - find the first @key in @tree
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining node order
 *
 * Returns the leftmost node matching @key, or NULL.
 */
static __always_inline struct ffkx_rb_node *rb_find_first(const void *key, const struct ffkx_rb_root *tree,
                                                          int (*cmp)(const void *key, const struct ffkx_rb_node *)) {
  struct ffkx_rb_node *node = tree->rb_node;
  struct ffkx_rb_node *match = NULL;

  ffkx_while(node) {
    int c = cmp(key, node);

    if (c <= 0) {
      if (!c) match = node;
      node = node->rb_left;
    } else if (c > 0) {
      node = node->rb_right;
    }
  }

  return match;
}

/**
 * rb_next_match() - find the next @key in @tree
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining node order
 *
 * Returns the next node matching @key, or NULL.
 */
static __always_inline struct ffkx_rb_node *rb_next_match(const void *key, struct ffkx_rb_node *node,
                                                          int (*cmp)(const void *key, const struct ffkx_rb_node *)) {
  node = rb_next(node);
  if (node && cmp(key, node)) node = NULL;
  return node;
}

/**
 * rb_for_each() - iterates a subtree matching @key
 * @node: iterator
 * @key: key to match
 * @tree: tree to search
 * @cmp: operator defining node order
 */
#define rb_for_each(node, key, tree, cmp)                                     \
  ffkx_for((node) = rb_find_first((key), (tree), (cmp)); ffkx_cond && (node); \
           (node) = rb_next_match((key), (node), (cmp)))

#endif
