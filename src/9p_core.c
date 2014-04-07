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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>      // gethostbyname
#include <sys/socket.h> // gethostbyname
#include <unistd.h>     // sleep
#include <inttypes.h>   // PRIu64
#include <fcntl.h>
#include <assert.h>
#include "9p_internals.h"
#include "utils.h"
#include "settings.h"


#if 0
static int p9ci_rebuild_fids(void *arg, struct rdx_node *node) {
	struct p9_handle *p9_handle = arg;
	int rc, flag = 0;
	struct p9_fid *fid;

	if (p9_handle == NULL || node == NULL)
		return EINVAL;

	fid = p9_rdx_fid(node);

	rc = p9p_rewalk(p9_handle->root_fid, fid->path, fid->fid);
	if (rc) {
		printf("rewalk failed on fid %p\n", fid);
		return rc;
	}

	if (fid->openflags) {
		switch (fid->openflags) {
		case RDFLAG:
			flag = O_RDONLY;
			break;
		case WRFLAG:
			flag = O_WRONLY;
			break;
		case RDFLAG|WRFLAG:
			flag = O_RDWR;
			break;
		default:
			break;
		}
		rc = p9p_lopen(fid, flag, NULL);
		if (rc)
			printf("re-lopen failed on fid %p\n", fid);
	}

	return rc;
}
#endif

int p9c_reconnect(struct p9_handle *p9_handle) {
	int sleeptime = 0;
	int rc = 0, i;
	struct ibv_mr *mr;


	pthread_mutex_lock(&p9_handle->connection_lock);

	while (!p9_handle->trans || p9_handle->trans->state != MSK_CONNECTED) {
		if (p9_handle->trans)
			p9_handle->net_ops->destroy_trans(&p9_handle->trans);

		if (sleeptime) {
			sleep(sleeptime);
			sleeptime = MIN(300,sleeptime*2);
		} else {
			sleeptime = 2;
		}

		/* mooshika init */
		rc = p9_handle->net_ops->init(&p9_handle->trans, &p9_handle->trans_attr);
		if (rc) {
			ERROR_LOG("msk_init failed: %s (%d)", strerror(rc), rc);
			continue;
		}

		p9_handle->trans->private_data = p9_handle;

		rc = p9_handle->net_ops->connect(p9_handle->trans);
		if (rc) {
			ERROR_LOG("msk_connect failed: %s (%d)", strerror(rc), rc);
			continue;
		}


		mr = p9_handle->net_ops->reg_mr(p9_handle->trans, p9_handle->rdmabuf, 2 * p9_handle->recv_num * p9_handle->msize, IBV_ACCESS_LOCAL_WRITE);
		if (mr == NULL) {
			ERROR_LOG("Could not register memory buffer");
			rc = EIO;
			continue;
		}

		for (i=0; i < p9_handle->recv_num; i++) {
			p9_handle->rdata[i].mr = mr;
			p9_handle->wdata[i].mr = mr;
			rc = p9_handle->net_ops->post_n_recv(p9_handle->trans, &p9_handle->rdata[i], 1, p9_recv_cb, p9_recv_err_cb, NULL);
			if (rc) {
				ERROR_LOG("Could not post recv buffer %i: %s (%d)", i, strerror(rc), rc);
				rc = EIO;
				break;
			}
		}
		if (rc)
			continue;

		rc = p9_handle->net_ops->finalize_connect(p9_handle->trans);
		if (rc) {
			ERROR_LOG("msk_finalize_connect failed: %s (%d)", strerror(rc), rc);
			continue;
		}

		rc = p9p_version(p9_handle);
		if (rc) {
			ERROR_LOG("version failed: %s (%d)", strerror(rc), rc);
			break;
		}

		rc = p9c_attach(p9_handle, p9_handle->uid, &p9_handle->root_fid);
		if (rc) {
			ERROR_LOG("attach failed: %s (%d)", strerror(rc), rc);
			break;
		}
	}

	pthread_mutex_unlock(&p9_handle->connection_lock);

	return rc;
}

int p9c_getbuffer(struct p9_handle *p9_handle, msk_data_t **pdata, uint16_t *ptag) {
	msk_data_t *data;
	uint32_t wdata_i, tag;

	pthread_mutex_lock(&p9_handle->credit_lock);
	while (p9_handle->credits == 0) {
		INFO_LOG(p9_handle->debug & P9_DEBUG_SEND, "waiting for credit (putreply)");
		pthread_cond_wait(&p9_handle->credit_cond, &p9_handle->credit_lock);
	}
	p9_handle->credits--;
	pthread_mutex_unlock(&p9_handle->credit_lock);

	pthread_mutex_lock(&p9_handle->wdata_lock);
	while ((wdata_i = get_and_set_first_bit(p9_handle->wdata_bitmap, p9_handle->recv_num)) == p9_handle->recv_num) {
		INFO_LOG(p9_handle->debug & P9_DEBUG_SEND, "waiting for wdata to free up (sendrequest's acknowledge callback)");
		pthread_cond_wait(&p9_handle->wdata_cond, &p9_handle->wdata_lock);
	}
	pthread_mutex_unlock(&p9_handle->wdata_lock);

	data = &p9_handle->wdata[wdata_i];
	data->size = 0;
	*pdata = data;

	pthread_mutex_lock(&p9_handle->tag_lock);
	/* kludge on P9_NOTAG to have a smaller array */
	if (*ptag == P9_NOTAG) {
		tag = p9_handle->max_tag-1;
		while(get_bit(p9_handle->tags_bitmap, tag))
			pthread_cond_wait(&p9_handle->tag_cond, &p9_handle->tag_lock);
		set_bit(p9_handle->tags_bitmap, tag);
	} else {
		while ((tag = get_and_set_first_bit(p9_handle->tags_bitmap, p9_handle->max_tag)) == p9_handle->max_tag)
			pthread_cond_wait(&p9_handle->tag_cond, &p9_handle->tag_lock);
	}
	pthread_mutex_unlock(&p9_handle->tag_lock);


	p9_handle->tags[tag].rdata = NULL;
	p9_handle->tags[tag].wdata_i = wdata_i;

	*ptag = (uint16_t)tag;
	return 0;
}


int p9c_sendrequest(struct p9_handle *p9_handle, msk_data_t *data, uint16_t tag) {
	int rc;

	rc = p9_handle->net_ops->post_n_send(p9_handle->trans, data, (data->next != NULL) ? 2 : 1, p9_send_cb, p9_send_err_cb, (void*)(uint64_t)tag);
	INFO_LOG(p9_handle->debug & P9_DEBUG_SEND, "sent request for tag %u", tag);

	if (rc) {
		p9c_reconnect(p9_handle);
		return p9c_sendrequest(p9_handle, data, tag);
	}

	return rc;
}


int p9c_abortrequest(struct p9_handle *p9_handle, msk_data_t *data, uint16_t tag) {
	/* release data and tag, getreply code */
	pthread_mutex_lock(&p9_handle->wdata_lock);
	clear_bit(p9_handle->wdata_bitmap, p9_handle->tags[tag].wdata_i);
	pthread_cond_signal(&p9_handle->wdata_cond);
	pthread_mutex_unlock(&p9_handle->wdata_lock);

	pthread_mutex_lock(&p9_handle->tag_lock);
	if (tag == P9_NOTAG)
		tag = p9_handle->max_tag -1;
	clear_bit(p9_handle->tags_bitmap, tag);
	pthread_cond_broadcast(&p9_handle->tag_cond);
	pthread_mutex_unlock(&p9_handle->tag_lock);

	/* ... and credit, putreply code */
	pthread_mutex_lock(&p9_handle->credit_lock);
	p9_handle->credits++;
	pthread_cond_broadcast(&p9_handle->credit_cond);
	pthread_mutex_unlock(&p9_handle->credit_lock);

	return 0;
}


int p9c_getreply(struct p9_handle *p9_handle, msk_data_t **pdata, uint16_t tag) {

	pthread_mutex_lock(&p9_handle->recv_lock);
	while (p9_handle->tags[tag].rdata == NULL && p9_handle->trans->state == MSK_CONNECTED) {
		pthread_cond_wait(&p9_handle->recv_cond, &p9_handle->recv_lock);
	}
	pthread_mutex_unlock(&p9_handle->recv_lock);

	if (p9_handle->trans->state != MSK_CONNECTED) {
		p9c_reconnect(p9_handle);
		p9c_sendrequest(p9_handle, &p9_handle->wdata[p9_handle->tags[tag].wdata_i], tag);
		return p9c_getreply(p9_handle, pdata, tag);
	}

	INFO_LOG(p9_handle->debug & P9_DEBUG_RECV, "ack reply for tag %u", tag);

	pthread_mutex_lock(&p9_handle->wdata_lock);
	clear_bit(p9_handle->wdata_bitmap, p9_handle->tags[tag].wdata_i);
	pthread_cond_signal(&p9_handle->wdata_cond);
	pthread_mutex_unlock(&p9_handle->wdata_lock);

	*pdata = p9_handle->tags[tag].rdata;
	pthread_mutex_lock(&p9_handle->tag_lock);
	if (tag == P9_NOTAG)
		tag = p9_handle->max_tag -1;
	clear_bit(p9_handle->tags_bitmap, tag);
	pthread_cond_broadcast(&p9_handle->tag_cond);
	pthread_mutex_unlock(&p9_handle->tag_lock);

	return 0;
}


int p9c_putreply(struct p9_handle *p9_handle, msk_data_t *data) {
	int rc;

	rc = p9_handle->net_ops->post_n_recv(p9_handle->trans, data, 1, p9_recv_cb, p9_recv_err_cb, NULL);
	if (rc) {
		ERROR_LOG("Could not post recv buffer %p: %s (%d)", data, strerror(rc), rc);
		rc = EIO;
	} else {
		pthread_mutex_lock(&p9_handle->credit_lock);
		p9_handle->credits++;
		pthread_cond_broadcast(&p9_handle->credit_cond);
		pthread_mutex_unlock(&p9_handle->credit_lock);
	}

	return rc;
}

static int p9ci_getfid(struct p9_handle *p9_handle, struct p9_fid **pfid) {
	struct p9_fid *fid;
	uint32_t fid_i;

	pthread_mutex_lock(&p9_handle->fid_lock);
	fid_i = get_and_set_first_bit(p9_handle->fids_bitmap, p9_handle->max_fid);
	pthread_mutex_unlock(&p9_handle->fid_lock);

	if (fid_i == p9_handle->max_fid)
		return ERANGE;

	fid = bucket_get(p9_handle->fids_bucket);
	if (fid == NULL) {
		pthread_mutex_lock(&p9_handle->fid_lock);
		clear_bit(p9_handle->fids_bitmap, fid_i);
		pthread_mutex_unlock(&p9_handle->fid_lock);
		return ENOMEM;
	}

	fid->p9_handle = p9_handle;
	fid->fid = fid_i;
	fid->openflags = 0;
	fid->type = -1;
	memset(&fid->qid, 0, sizeof(struct p9_qid));
	fid->offset = 0L;
	fid->rdx_node = default_rdx_node;
	*pfid = fid;
	return 0;
}

static void p9ci_addfid(struct p9_fid *parent_fid, struct p9_fid **pfid, const char *path) {
	struct rdx_node *exists;
	struct p9_fid *new_fid = *pfid;

	new_fid->fid_path = strdup(path);


	exists = rdx_insert(&parent_fid->rdx_node, &new_fid->rdx_node);

	if (exists) {
		*pfid = p9_rdx_fid(exists);
		INFO_LOG(new_fid->p9_handle->debug & P9_DEBUG_CORE, "%p: %"PRIu64" (%i, %s) insert on exist", *pfid, (*pfid)->rdx_node.refcnt, (*pfid)->fid, (*pfid)->fid_path);
		p9c_putfidcb(&new_fid->rdx_node);
	} else {
		INFO_LOG(new_fid->p9_handle->debug & P9_DEBUG_CORE, "%p: %"PRIu64" (%i, %s) insert new", new_fid, new_fid->rdx_node.refcnt, new_fid->fid, new_fid->fid_path);
	}

}

static void p9ci_invalidfid(struct p9_handle *p9_handle, struct p9_fid *fid) {
	pthread_mutex_lock(&p9_handle->fid_lock);
	clear_bit(p9_handle->fids_bitmap, fid->fid);
	pthread_mutex_unlock(&p9_handle->fid_lock);

	bucket_put(p9_handle->fids_bucket, (void*)fid);
}

int p9c_putfidcb(struct rdx_node *node) {
	struct p9_fid *fid;
	struct p9_handle *p9_handle;

	if (node == NULL)
		return EINVAL;

	fid = p9_rdx_fid(node);

	p9_handle = fid->p9_handle;
	if (p9_handle == NULL)
		return EINVAL;

	INFO_LOG(p9_handle->debug & P9_DEBUG_CORE, "%p (%i, %s, refcnt %"PRIu64") being destroyed", fid, fid->fid, fid->fid_path, fid->rdx_node.refcnt);

	p9p_clunk(fid);

	pthread_mutex_lock(&p9_handle->fid_lock);
	clear_bit(p9_handle->fids_bitmap, fid->fid);
	pthread_mutex_unlock(&p9_handle->fid_lock);

	/* need the cast because we can't free const... */
	free((char*)fid->fid_path);
	fid->fid_path = (const char*)0xdeaddeaddeaddead;

	bucket_put(p9_handle->fids_bucket, (void*)fid);

	return 0;
}

int p9c_putfid(struct p9_fid **pfid) {
	switch ((*pfid)->type) {
		case P9_FID_ATTACH:
			break;

		case P9_FID_WALK:
			INFO_LOG((*pfid)->p9_handle->debug & P9_DEBUG_CORE, "%p: %"PRIu64" (%i, %s)", (*pfid), (*pfid)->rdx_node.refcnt, (*pfid)->fid, (*pfid)->fid_path);
			/* does all the work, somehow */
			rdx_unref(&(*pfid)->rdx_node);
			break;

		case P9_FID_XATTR:
			p9c_putfidcb(&(*pfid)->rdx_node);
			break;

		default:
			ERROR_LOG("not a known fid type?! %p", *pfid);
			return EINVAL;
	}

	*pfid = NULL;
	return 0;
}

int p9c_takefid(struct p9_fid *fid) {
	switch (fid->type) {
                case P9_FID_ATTACH:
                        break;

                case P9_FID_WALK:
			INFO_LOG(fid->p9_handle->debug & P9_DEBUG_CORE, "%p: %"PRIu64" (%i, %s)", fid, fid->rdx_node.refcnt, fid->fid, fid->fid_path);

                        rdx_ref(&fid->rdx_node);
	                break;

                case P9_FID_XATTR:
			ERROR_LOG("refs don't make sense on xattr fid %p", fid);
			return EINVAL;

                default:
                        ERROR_LOG("not a known fid type?! %p", fid);
                        return EINVAL;
        }

        return 0;
}


int p9c_attach(struct p9_handle *p9_handle, uint32_t uid, struct p9_fid **pfid) {
	int rc;
	struct p9_fid *fid;

	/* Sanity check */
	if (p9_handle == NULL || pfid == NULL)
		return EINVAL;

	rc = p9ci_getfid(p9_handle, &fid);
	if (rc) {
		ERROR_LOG("not enough fids - failing attach");
		return rc;
	}

	rc = p9p_attach(p9_handle, uid, fid);
	if (rc) {
		ERROR_LOG("attach failed: %d", rc);
		p9ci_invalidfid(p9_handle, fid);
		return rc;
	}

	/* attach is out of tree, there's no addfid */
	fid->type = P9_FID_ATTACH;
	*pfid = fid;

	return 0;
}

int p9c_walk(struct p9_fid *fid, char *path, struct p9_fid **pnewfid) {
	int rc;
	struct p9_fid *newfid;
	struct p9_handle *p9_handle;
	struct rdx_node *node;
	char *path_left;

	/* Sanity check */
	if (fid == NULL || fid->p9_handle == NULL || pnewfid == NULL)
		return EINVAL;

	p9_handle = fid->p9_handle;

	if (strchr(path, '/')) {
		ERROR_LOG("Can't walk compound path - we need to check that all subpaths exist");
		return EINVAL;
	}

	/* Check if we have it first */
	node = rdx_lookup(&fid->rdx_node, path, &path_left);

	if (path_left == NULL) {
		*pnewfid = p9_rdx_fid(node);
		INFO_LOG(p9_handle->debug & P9_DEBUG_CORE, "%p: %"PRIu64" lookup match", *pnewfid, (*pnewfid)->rdx_node.refcnt);
		return 0;
	}

	rc = p9ci_getfid(p9_handle, &newfid);
	if (rc) {
		ERROR_LOG("not enough fids - failing walk");
		return rc;
	}

	rc = p9p_walk(fid, path, newfid);
	if (rc) {
		rdx_unref(&fid->rdx_node);
		p9ci_invalidfid(fid->p9_handle, newfid);
		return rc;
	}

	newfid->type = P9_FID_WALK;
	p9ci_addfid(fid, &newfid, path);

	*pnewfid = newfid;

	return 0;
}

int p9c_xattrwalk(struct p9_fid *fid, struct p9_fid **pnewfid, char *name, uint64_t *psize) {
	int rc;
	struct p9_fid *newfid;
	struct p9_handle *p9_handle;

	/* Sanity check */
	if (fid == NULL || fid->p9_handle == NULL || pnewfid == NULL || name == NULL || psize == NULL)
		return EINVAL;

	p9_handle = fid->p9_handle;

	rc = p9ci_getfid(p9_handle, &newfid);
	if (rc) {
		ERROR_LOG("not enough fids - failing xattrwalk");
		return rc;
	}

	rc = p9p_xattrwalk(fid, newfid, name, psize);
	if (rc) {
		ERROR_LOG("xattrwalk failed: %d", rc);
		p9ci_invalidfid(p9_handle, newfid);
		return rc;
	}

	/* attach is out of tree, there's no addfid */
	newfid->type = P9_FID_XATTR;
	newfid->fid_path = strdup(fid->fid_path);
	*pnewfid = newfid;

	return 0;
}

int p9c_lcreate(struct p9_fid **pfid, char *name, uint32_t flags, uint32_t mode,
               uint32_t gid, uint32_t *iounit) {
	int rc;
	struct p9_fid *fid, *newfid;
	struct p9_handle *p9_handle;

	/* Sanity check */
	if (pfid == NULL || *pfid == NULL || (*pfid)->p9_handle == NULL)
		return EINVAL;

	fid = *pfid;
	p9_handle = fid->p9_handle;

	rc = p9ci_getfid(p9_handle, &newfid);
	if (rc) {
		ERROR_LOG("not enough fids - failing attach");
		return rc;
	}

	rc = p9p_walk(fid, NULL, newfid);
	if (rc) {
		p9ci_invalidfid(fid->p9_handle, newfid);
		return rc;
	}

	newfid->type = P9_FID_XATTR;

	rc = p9p_lcreate(newfid, name, flags, mode, gid, iounit);
	if (rc) {
		p9c_putfidcb(&newfid->rdx_node);
		return rc;
	}


	newfid->fid_path = strdup(fid->fid_path);
	p9c_putfid(&fid);

	*pfid = newfid;

	return 0;
}

int p9c_reg_mr(struct p9_handle *p9_handle, msk_data_t *data) {
	data->mr = p9_handle->net_ops->reg_mr(p9_handle->trans, data->data, data->max_size, IBV_ACCESS_LOCAL_WRITE);
#if HAVE_MOOSHIKA
	if (data->mr == NULL) {
		return -1;
	}
#endif
	return 0;
}

int p9c_dereg_mr(struct p9_handle *p9_handle, msk_data_t *data) {
	return p9_handle->net_ops->dereg_mr(data->mr);
}
