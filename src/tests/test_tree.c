/*
 * Copyright CEA/DAM/DIF (2013)
 * Contributor: Dominique Martinet <dominique.martinet@cea.fr>
 *
 * This file is part of the space9 9P userspace library.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with space9.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../rdx_tree.h"

#define DEFAULT_SIZE 1024
#define DEPTH 100
#define WIDTH 100
#define NNODES (WIDTH*DEPTH)
#define NUM_THR 10
struct rdx_node root = DEFAULT_RDX_NODE;


void *thr(void *arg) {
	int thrn = (int)(uint64_t)arg;
	struct rdx_node nodes[NNODES], *pnode, *parent;
	char path[NNODES][64], *rpath, lpath[MAXPATHLEN];
	int i, j, rc;
	struct drand48_data randdata;
	long int rval;

	seed48_r((unsigned short int*)"12345", &randdata);

	root.node_path = "/";
	memset(nodes, NNODES*sizeof(*nodes), 0);

	/* mass insert in a single rbtree and lookup */
	for (i = 0; i < NNODES; i++) {
		nodes[i].node_path = path[i];
		snprintf(path[i], MAXNAMLEN, "%i.%i", thrn, i);
		pnode = rdx_insert(&root, &nodes[i]);
		if (pnode) {
			printf("%i: insert: %p found (node %i)\n", thrn, pnode, i);
		}
	}
	for (i = 0; i < NNODES; i++) {
		pnode = rdx_lookup(&root, path[i], &rpath);
		if (rpath != NULL || pnode != &nodes[i]) {
			printf("%i: lookup: rpath: %p, pnode: %p,, node %i: %p\n",
			       thrn, rpath, pnode, i, &nodes[i]);
			exit(1);
		}
		rdx_unref(pnode);
	}

	/* remove some and lookup again */
	for (i = 0; i < NNODES; i+=2) { 
		rdx_unref(&nodes[i]);
	}

	for (i = 1; i < NNODES; i+=2) { 
		pnode = rdx_lookup(&root, path[i], &rpath);
		if (rpath != NULL || pnode != &nodes[i]) {
			printf("%i: lookup: rpath: %p, pnode: %p,, node %i: %p\n",
			       thrn, rpath, pnode, i, &nodes[i]);
			exit(1);
		}
		rdx_unref(pnode);
	}

	/* finish cleaning */
	for (i = 1; i < NNODES; i+=2) { 
		rdx_unref(&nodes[i]);
	}

	/* insert to some depth */
	parent = &root;
	for (i = 0; i < DEPTH; i++) {
		for (j = 0; j < WIDTH; j++) {
			if (i > 0) {
				lrand48_r(&randdata, &rval);
				parent = &nodes[WIDTH*(i-1) + (rval%WIDTH)];
			}

			pnode = rdx_insert(parent, &nodes[WIDTH*i+j]);
	                if (pnode) {
        	                printf("%i: insert: %p found (node %i)\n", thrn, pnode, i);
                	}
       		}
	}

	for (i = 0; i < NNODES; i++) {
		parent = &nodes[i];
		rpath = lpath + MAXPATHLEN;
		while(parent) {
			j = strlen(parent->node_path);
			if (rpath < lpath + j + 1) {
				lpath[MAXPATHLEN-1] = '\0';
				printf("%i: path too long to fit? got %s so far\n", thrn, rpath);
				exit(1);
			}
			rpath -= j+1; // 1 for /
			rc = snprintf(rpath, j+1, "%s", parent->node_path);
			if (rc != j) {
				printf("%i: expected to write %d, wrote %d bytes\n", thrn, j, rc);
				exit(1);
			}
			rpath[j] = '/';
			parent = parent->parent;
		}
		lpath[MAXPATHLEN-1] = '\0';

		pnode = rdx_lookup(&root, rpath, &rpath);
		if (rpath != NULL || pnode != &nodes[i]) {
			printf("%i: lookup: rpath: %p, pnode: %p,, node %i: %p\n",
			       thrn, rpath, pnode, i, &nodes[i]);
			exit(1);
		}
		rdx_unref(pnode);
	}
	

	for (i = 0; i < NNODES; i++) {
		rdx_unref(&nodes[i]);
	}


	return (NULL);
}

int main() {
	pthread_t thrid[NUM_THR];
	int i;

	for (i=0; i<NUM_THR; i++) {
		pthread_create(&thrid[i], NULL, thr, (void*)(uint64_t)i);
	}

	for (i=0; i<NUM_THR; i++) {
		pthread_join(thrid[i], NULL);
	}

	return 0;
}
