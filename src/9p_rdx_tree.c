#include "rdx_tree.h"
#include "utils.h"

//RB_GENERATE(rb_tree, rb_node, rb_link, rb_node_cmp);
RB_GENERATE_STATIC(rb_tree, rb_node, rb_link, rb_node_cmp);



/**
 * Unref/ref helpers (apply only on current node):
 *
 * If something goes to 0, we *re-increment* it and mark it for deletion.
 * This is because we are going to drop the lock and we don't want another
 * thread to delete it while we still haev it pointed.
 * Last call to delete (ordered thanks to wrlock) will do the actual delete.
 */
static inline struct rdx_node *rdx_unref_node(struct rdx_node *node) {
	struct rdx_node *parent = node->parent;

	/* root entry has no parent/refcnt */
	if (!parent)
		return NULL;

	pthread_rwlock_rdlock(&parent->rwlock);

	if (atomic_postdec(node->refcnt) == 0) {
		atomic_inc(node->refcnt);
		pthread_rwlock_unlock(&parent->rwlock);
		rdx_delete(node);
	} else {
		pthread_rwlock_unlock(&parent->rwlock);
	}

	return parent;
}

static inline void rdx_ref_node(struct rdx_node *node) {
	struct rdx_node *parent = node->parent;

	if (!parent)
		return;

	pthread_rwlock_rdlock(&parent->rwlock);

	atomic_inc(node->refcnt);

	pthread_rwlock_unlock(&parent->rwlock);

	return;	
}


/**
 * Insert:
 *
 * Only inserts directly from parent directory node.
 *
 */
struct rdx_node *rdx_insert(struct rdx_node *parent, struct rdx_node *entry) {
	struct rb_node *node;
	struct rdx_node *match;

	pthread_rwlock_wrlock(&parent->rwlock);
	node = RB_INSERT(rb_tree, &parent->child, &entry->rb_node);
	pthread_rwlock_unlock(&parent->rwlock);

	if (node) {
		match = container_of(node, struct rdx_node, rb_node);
		rdx_ref_node(match);
		return match;
	}

	entry->parent = parent;
	entry->refcnt = 1;

	return NULL;
}


/**
 * Delete:
 *
 * Failures:
 * - EADDRINUSE: Someone else re-used the node before we're down to deleting
 * - ENOENT: Node wasn't there for some reason
 */
int rdx_delete(struct rdx_node *entry) {
	int rc = EADDRINUSE;
	struct rdx_node *parent = entry->parent;


	/* root entry has no parent/refcnt */
	if (!parent)
		return 0;

	pthread_rwlock_wrlock(&parent->rwlock);
	/* check that no-one else reincremented or tried to delete it first */
	if (atomic_postdec(entry->refcnt) == 0) {
		if (RB_REMOVE(rb_tree, &parent->child, &entry->rb_node))
			rc = 0;
		else
			rc = ENOENT;
	}
	pthread_rwlock_unlock(&parent->rwlock);

	if (!rc) {
		//printf("callback(entry)\n");
	}

	return 0;
}

/**
 * Starts from leaf node and goes back up.
 *
 */
void rdx_unref(struct rdx_node *node) {
	while ((node = rdx_unref_node(node)));
}


/**
 * Lookup:
 *
 * Find it.
 * Increment every refcnt on the way, woo.
 * Return closest node if not found - no need to unref.
 * remaining_path is NULL if found, contains what's left to walk otherwise.
 */
struct rdx_node *rdx_lookup(struct rdx_node *node, char *path, char **remaining_path) {
	char *slash;
	struct rb_node *match, key;
	struct rdx_node *parent;

	do {
		slash = strchr(path, '/');
		if (slash) {
			/* either leading / or a path like // */
			if (slash == path) {
				path++;
				continue;
			}
			slash[0]='\0';
		}
		/* special cases: ., .. */
		if (strcmp(path, ".") == 0) {
			path = slash + 1;
			continue;
		}
		if (strcmp(path, "..") == 0) {

			/* root node doesn't get unref'd */
       			if (node->parent != NULL)
				node = rdx_unref_node(node);
			path = slash + 1;
			continue;
		}
		key.path = path;
		parent = node;
		pthread_rwlock_rdlock(&parent->rwlock);
		match = RB_FIND(rb_tree, &parent->child, &key);
		if (match) {
			node = container_of(match, struct rdx_node, rb_node);
		} else {
			pthread_rwlock_unlock(&parent->rwlock);
			break;
		}

		atomic_inc(node->refcnt);
		pthread_rwlock_unlock(&parent->rwlock);


		if (slash) {
			slash[0]='/';
			path = slash + 1;
		} else {
			path = NULL;
		}
	} while (path);

	*remaining_path = path;

	return node;
}
