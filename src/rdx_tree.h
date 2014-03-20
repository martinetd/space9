#ifndef _RDX_TREE_H
#define _RDX_TREE_H

#include <string.h>
#include "9p_internals.h"
#include "bsd_tree.h"

struct rb_node {
	RB_ENTRY(rb_node) rb_link;
	const char *path;
	// uint64_t path_hash; does that really help?
};

RB_HEAD(rb_tree, rb_node);

static inline int rb_node_cmp(struct rb_node *nA, struct rb_node *nB) {
	return strcmp(nA->path, nB->path);
}

//RB_PROTOTYPE(rb_tree, rb_node, rb_link, rb_node_cmp);

/**
 * tree:
 *
 * Radix tree, so:
 * No void *value: the node is embedded in a fid or another structure
 * (there can't be an empty node)
 */

struct rdx_node {
	struct rb_node rb_node;
#define node_path rb_node.path
	struct rdx_node *parent;
	struct rb_tree child;
	pthread_rwlock_t rwlock;
	uint64_t refcnt;
};

/* default node: everything is 0 */
#define DEFAULT_RDX_NODE { .rwlock = PTHREAD_RWLOCK_INITIALIZER }

typedef void (*delete_cb_t)(struct rdx_node *node);

/**
 * Insert:
 *
 * Only inserts directly from parent directory node.
 *
 */
struct rdx_node *rdx_insert(struct rdx_node *parent, struct rdx_node *entry);

/**
 * Delete:
 *
 * Failures:
 * - EADDRINUSE: Someone else re-used the node before we're down to deleting
 * - ENOENT: Node wasn't there for some reason
 */
int rdx_delete(struct rdx_node *entry);
/**
 * Lookup:
 *
 * Find it.
 * Increment every refcnt on the way, woo.
 * Return closest node if not found - no need to unref.
 * remaining_path is NULL if found, contains what's left to walk otherwise.
 */
struct rdx_node *rdx_lookup(struct rdx_node *node, char *path, char **remaining_path);

/**
 * Unref:
 *
 * Starts from leaf node and goes back up.
 * If something goes to 0, we *re-increment* it and mark it for deletion.
 * This is because we are going to drop the lock and we don't want another
 * thread to delete it while we still haev it pointed.
 * Last call to delete (ordered thanks to wrlock) will do the actual delete.
 */
void rdx_unref(struct rdx_node *node);

#endif
