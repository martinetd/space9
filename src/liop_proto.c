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

#include <stdio.h>
#include <inttypes.h> // PRIu64
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "9p_internals.h"
#include "9p_proto_internals.h"
#include "liop_proto_internals.h"
#include "utils.h"


int liop_status(struct p9_handle *p9_handle, char *fsname) {
        int rc;
        msk_data_t *data;
        uint16_t tag = 0;
        uint16_t msgtype;
        uint8_t *cursor;

        /* Sanity check */
        if (p9_handle == NULL || p9_handle->proto != PROTO_LIOP || fsname == NULL)
                return EINVAL;

	rc = p9c_getbuffer(p9_handle, &data, &tag);
	if (rc != 0)
		return rc;

	liop_initcursor(cursor, data->data, LIOP_TSTATUS, tag);
	p9_setstr(cursor, strlen(fsname), fsname);
	p9_setmsglen(cursor, data);

	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "liopstatus on fs %s", fsname);

	rc = p9c_sendrequest(p9_handle, data, tag);
	if (rc != 0)
		return rc;

	rc = p9c_getreply(p9_handle, &data, tag);
	if (rc != 0)
		return rc;

	cursor = data->data;
	liop_getheader(cursor, msgtype);
	switch (msgtype) {
		case LIOP_RSTATUS:
			p9_getvalue(cursor, rc, uint32_t);
			printf("status %d\n", rc);
			rc = 0;
			break;

		case LIOP_RERROR:
			p9_getvalue(cursor, rc, uint32_t);
			if (rc == 0) {
				ERROR_LOG("Got LIOP_ERROR but no rc set, msg %u/tag %u", LIOP_TSTATUS, tag);
				rc = EIO;
			}
			break;

		default:
			ERROR_LOG("Wrong reply type %u to msg %u/tag %u", msgtype, LIOP_TSTATUS, tag);
			rc = EIO;
	}

	p9c_putreply(p9_handle, data);

	return rc;
}

int liop_gethandle(struct p9_handle *p9_handle, char *fsname, char *path,
		   uint32_t uid, struct file_handle **pfhandle) {
        int rc;
        msk_data_t *data;
        uint16_t tag = 0;
        uint16_t msgtype;
        uint8_t *cursor;
	uint32_t handle_bytes;
	struct file_handle *fhandle;

        /* Sanity check */
        if (p9_handle == NULL || p9_handle->proto != PROTO_LIOP || fsname == NULL || path == NULL || pfhandle == NULL)
                return EINVAL;

	rc = p9c_getbuffer(p9_handle, &data, &tag);
	if (rc != 0)
		return rc;

	liop_initcursor(cursor, data->data, LIOP_TGETHANDLE, tag);
	p9_setstr(cursor, strlen(fsname), fsname);
	p9_setstr(cursor, strlen(path), path);
	p9_setvalue(cursor, uid, uint32_t);
	p9_setmsglen(cursor, data);

	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "liopgetfid on fs %s path %s", fsname, path);

	rc = p9c_sendrequest(p9_handle, data, tag);
	if (rc != 0)
		return rc;

	rc = p9c_getreply(p9_handle, &data, tag);
	if (rc != 0)
		return rc;

	cursor = data->data;
	liop_getheader(cursor, msgtype);
	switch (msgtype) {
		case LIOP_RGETHANDLE:
			p9_getvalue(cursor, handle_bytes, uint32_t);
			if (handle_bytes > MAX_HANDLE_SZ) {
				ERROR_LOG("Got given a handle bigger than max size (%d > %d), msg %u/tag %u",
					  handle_bytes, MAX_HANDLE_SZ, LIOP_TGETHANDLE, tag);
				rc = EIO;
				break;
			}
			fhandle = malloc(sizeof(struct file_handle)+handle_bytes);
			if (fhandle == NULL) {
				ERROR_LOG("could not allocate handle (size %d), msg %u/tag %u",
					  handle_bytes, LIOP_TGETHANDLE, tag);
				rc = ENOMEM;
				break;
			}
			fhandle->handle_bytes = handle_bytes;
			p9_getvalue(cursor, fhandle->handle_type, uint32_t);
			memcpy(fhandle->f_handle, cursor, handle_bytes);
			*pfhandle = fhandle;
			break;

		case LIOP_RERROR:
			p9_getvalue(cursor, rc, uint32_t);
			if (rc == 0) {
				ERROR_LOG("Got LIOP_ERROR but no rc set, msg %u/tag %u", LIOP_TGETHANDLE, tag);
				rc = EIO;
			}
			break;

		default:
			ERROR_LOG("Wrong reply type %u to msg %u/tag %u", msgtype, LIOP_TGETHANDLE, tag);
			rc = EIO;
	}

	p9c_putreply(p9_handle, data);

	return rc;
}

ssize_t liopz_read_send(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
			uint32_t uid, size_t count, uint64_t offset, uint16_t *ptag) {
	ssize_t rc;
	msk_data_t *data;
	uint16_t tag;
	uint8_t *cursor;

	/* Sanity check */
	if (p9_handle == NULL || fsname == NULL || fhandle == NULL || ptag == NULL || count == 0)
		return -EINVAL;


	tag = 0;
	rc = p9c_getbuffer(p9_handle, &data, &tag);
	if (rc != 0)
		return -rc;

	count = liop_read_len(p9_handle, count);

	liop_initcursor(cursor, data->data, LIOP_TREAD, tag);
	p9_setstr(cursor, strlen(fsname), fsname);
	p9_sethandle(cursor, fhandle);
	p9_setvalue(cursor, uid, uint32_t);
	p9_setvalue(cursor, offset, uint64_t);
	p9_setvalue(cursor, count, uint32_t);
	p9_setmsglen(cursor, data);

	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "read offset %"PRIu64", count %zi", offset, count);

	rc = p9c_sendrequest(p9_handle, data, tag);
	if (rc != 0)
		return -rc;

	*ptag = tag;
	return 0;
}

ssize_t liopz_read_wait(struct p9_handle *p9_handle, msk_data_t **pdata, uint16_t tag) {
	ssize_t rc;
	msk_data_t *data;
	uint8_t msgtype;
	uint8_t *cursor;

	if (pdata == NULL)
		return -EINVAL;

	rc = p9c_getreply(p9_handle, &data, tag);
	if (rc != 0)
		return -rc;

	cursor = data->data;
	liop_getheader(cursor, msgtype);
	switch(msgtype) {
		case LIOP_RREAD:
			p9_getvalue(cursor, rc, uint32_t);
			data->data += LIOP_RREAD_HDR_SIZE;
			data->size -= LIOP_RREAD_HDR_SIZE;
			*pdata = data;
			break;

		case LIOP_RERROR:
			p9_getvalue(cursor, rc, uint32_t);
			p9c_putreply(p9_handle, data);
			rc = -rc;
			if (rc == 0) {
				ERROR_LOG("Got LIOP_ERROR but no rc set, msg %u/tag %u", LIOP_TREAD, tag);
				rc = -EIO;
			}
			break;

		default:
			p9c_putreply(p9_handle, data);
			ERROR_LOG("Wrong reply type %u to msg %u/tag %u", msgtype, LIOP_TREAD, tag);
			rc = -EIO;
	}

	return rc;
}

ssize_t liopz_read(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
		   uint32_t uid, size_t count, uint64_t offset, msk_data_t **pdata) {
	ssize_t rc;
	uint16_t tag;

	if (pdata == NULL)
		return -EINVAL;

	rc = liopz_read_send(p9_handle, fsname, fhandle, uid, count, offset, &tag);
	if (rc)
		return rc;

	return liopz_read_wait(p9_handle, pdata, tag);
}

ssize_t liop_read(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
		  uint32_t uid, char *buf, size_t count, uint64_t offset) {
	msk_data_t *data;
	ssize_t rc;

	rc = liopz_read(p9_handle, fsname, fhandle, uid, count, offset, &data);

	if (rc >= 0) {
		memcpy(buf, data->data, MIN(count, rc));
		liopz_read_put(p9_handle, data);
	}

	return rc;
}


ssize_t liopz_write_send(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
			 uint32_t uid, msk_data_t *data, uint64_t offset, uint16_t *ptag) {
	ssize_t rc;
	msk_data_t *header_data;
	uint16_t tag;
	uint8_t *cursor;

	/* Sanity check */
	if (p9_handle == NULL || fsname == NULL || fhandle == NULL || data == NULL || data->size == 0)
		return -EINVAL;

	tag = 0;
	rc = p9c_getbuffer(p9_handle, &header_data, &tag);
	if (rc != 0 || header_data == NULL)
		return -rc;

	data->size = liop_write_len(p9_handle, data->size, strlen(fsname) + fhandle->handle_bytes);

	liop_initcursor(cursor, header_data->data, LIOP_TWRITE, tag);
	p9_setstr(cursor, strlen(fsname), fsname);
	p9_sethandle(cursor, fhandle);
	p9_setvalue(cursor, uid, uint32_t);
	p9_setvalue(cursor, offset, uint64_t);
	p9_setvalue(cursor, data->size, uint32_t);
	liop_padding(cursor, header_data->data);
	p9_setmsglen(cursor, header_data);
	*((uint32_t*)header_data->data) = header_data->size + data->size;

	header_data->next = data;

	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "write tag %u, fid X, offset %"PRIu64", count %u", tag, offset, data->size);

	rc = p9c_sendrequest(p9_handle, header_data, tag);
	if (rc != 0)
		return -rc;

	*ptag = tag;
	return 0;
}

ssize_t liopz_write_wait(struct p9_handle *p9_handle, uint16_t tag) {
	ssize_t rc;
	msk_data_t *data;
	uint8_t *cursor;
	uint16_t msgtype;

	rc = p9c_getreply(p9_handle, &data, tag);
	if (rc != 0)
		return -rc;

	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "writewait tag %u", tag);

	cursor = data->data;
	liop_getheader(cursor, msgtype);
	switch(msgtype) {
		case LIOP_RWRITE:
			p9_getvalue(cursor, rc, uint32_t);
			break;

		case LIOP_RERROR:
			p9_getvalue(cursor, rc, uint32_t);
			rc = -rc;
			if (rc == 0) {
				ERROR_LOG("Got 9P_RERROR but no rc set, msg %u/tag %u", LIOP_TWRITE, tag);
				rc = -EIO;
			}
			break;

		default:
			ERROR_LOG("Wrong reply type %u to msg %u/tag %u", msgtype, LIOP_TWRITE, tag);
			rc = -EIO;
	}

	p9c_putreply(p9_handle, data);

	return rc;
}

ssize_t liopz_write(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
		    uint32_t uid, msk_data_t *data, uint64_t offset) {
	ssize_t rc;
	uint16_t tag;

	rc = liopz_write_send(p9_handle, fsname, fhandle, uid, data, offset, &tag);
	if (rc)
		return rc;

	return liopz_write_wait(p9_handle, tag);
}

ssize_t liop_write_send(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
			uint32_t uid, char *buf, size_t count, uint64_t offset, uint16_t *ptag) {
	ssize_t rc;
	msk_data_t *data;
	uint16_t tag;
	uint8_t *cursor;

	/* Sanity check */
	if (p9_handle == NULL || fsname == NULL || fhandle == NULL || buf == NULL)
		return -EINVAL;

	if (count == 0)
		return 0;

	tag = 0;
	rc = p9c_getbuffer(p9_handle, &data, &tag);
	if (rc != 0)
		return -rc;

	count = liop_write_len(p9_handle, count, strlen(fsname) + fhandle->handle_bytes);

	liop_initcursor(cursor, data->data, LIOP_TWRITE, tag);
	p9_setstr(cursor, strlen(fsname), fsname);
	p9_sethandle(cursor, fhandle);
	p9_setvalue(cursor, uid, uint32_t);
	p9_setvalue(cursor, offset, uint64_t);
	p9_setvalue(cursor, count, uint32_t);
	liop_padding(cursor, data->data);
	memcpy(cursor, buf, count);
	cursor += count;
	p9_setmsglen(cursor, data);


	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "write fid X, offset %"PRIu64", count %zu", offset, count);

	rc = p9c_sendrequest(p9_handle, data, tag);
	if (rc != 0)
		return -rc;

	*ptag = tag;
	return 0;
}

ssize_t liop_write_wait(struct p9_handle *p9_handle, uint16_t tag) {
	ssize_t rc;
	msk_data_t *data;
	uint16_t msgtype;
	uint8_t *cursor;

	rc = p9c_getreply(p9_handle, &data, tag);
	if (rc != 0)
		return -rc;

	cursor = data->data;
	liop_getheader(cursor, msgtype);
	switch(msgtype) {
		case LIOP_RWRITE:
			p9_getvalue(cursor, rc, uint32_t);
			break;

		case LIOP_RERROR:
			p9_getvalue(cursor, rc, uint32_t);
			rc = -rc;
			if (rc == 0) {
				ERROR_LOG("Got 9P_RERROR but no rc set, msg %u/tag %u", LIOP_TWRITE, tag);
				rc = -EIO;
			}
			break;

		default:
			ERROR_LOG("Wrong reply type %u to msg %u/tag %u", msgtype, LIOP_TWRITE, tag);
			rc = -EIO;
	}

	p9c_putreply(p9_handle, data);

	return rc;
}

ssize_t liop_write(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
		   uint32_t uid, char *buf, size_t count, uint64_t offset) {
	ssize_t rc;
	uint16_t tag;

	rc = liop_write_send(p9_handle, fsname, fhandle, uid, buf, count, offset, &tag);
	if (rc)
		return rc;

	return liop_write_wait(p9_handle, tag);
}



ssize_t liop_write_rdma_init(struct p9_handle *p9_handle, char *fsname, struct file_handle *fhandle,
			     uint32_t uid, uint64_t offset, uint32_t count, uint64_t *preqid,
			     uint32_t *pcount, msk_rloc_t **prloc) {
        int rc;
        msk_data_t *data;
        uint16_t tag = 0;
        uint16_t msgtype;
        uint8_t *cursor;
	uint64_t reqid;
	uint32_t numrloc;
	msk_rloc_t *rloc;
	

        /* Sanity check */
        if (p9_handle == NULL || p9_handle->proto != PROTO_LIOP || fsname == NULL || fhandle == NULL
	    || preqid == NULL || pcount == NULL || prloc == NULL)
                return -EINVAL;

	rc = p9c_getbuffer(p9_handle, &data, &tag);
	if (rc != 0)
		return -rc;

	liop_initcursor(cursor, data->data, LIOP_TWRITE_RDMA_INIT, tag);
	p9_setstr(cursor, strlen(fsname), fsname);
	p9_sethandle(cursor, fhandle);
	p9_setvalue(cursor, uid, uint32_t);
	p9_setvalue(cursor, offset, uint64_t);
	p9_setvalue(cursor, count, uint32_t);
	p9_setmsglen(cursor, data);

	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "liopstatus on fs %s", fsname);

	rc = p9c_sendrequest(p9_handle, data, tag);
	if (rc != 0)
		return -rc;

	rc = p9c_getreply(p9_handle, &data, tag);
	if (rc != 0)
		return -rc;

	cursor = data->data;
	liop_getheader(cursor, msgtype);
	switch (msgtype) {
		case LIOP_RWRITE_RDMA_INIT:
			p9_getvalue(cursor, reqid, uint64_t);
			p9_getvalue(cursor, rc, uint32_t);
			p9_getvalue(cursor, numrloc, uint32_t);
			rloc = malloc(sizeof(msk_rloc_t)*numrloc);
			if (rloc == NULL) {
				ERROR_LOG("Could not allocate %d msk_rloc_t, aborting msg %u/tag%u", numrloc, LIOP_TWRITE_RDMA_INIT, tag);
				rc = -ENOMEM;
				break;
			}
			*preqid = reqid;
			*pcount = numrloc;
			*prloc = rloc;
			while (numrloc-- > 0) {
				p9_getvalue(cursor, rloc->raddr, uint64_t);
				p9_getvalue(cursor, rloc->rkey, uint32_t);
				p9_getvalue(cursor, rloc->size, uint32_t);
				rloc++;
			}
			
			break;

		case LIOP_RERROR:
			p9_getvalue(cursor, rc, uint32_t);
			if (rc == 0) {
				ERROR_LOG("Got LIOP_ERROR but no rc set, msg %u/tag %u", LIOP_TWRITE_RDMA_INIT, tag);
				rc = -EIO;
			}
			break;

		default:
			ERROR_LOG("Wrong reply type %u to msg %u/tag %u", msgtype, LIOP_TWRITE_RDMA_INIT, tag);
			rc = -EIO;
	}

	p9c_putreply(p9_handle, data);

	return rc;
}

int liop_write_rdma_fini(struct p9_handle *p9_handle, uint64_t reqid) {
        int rc;
        msk_data_t *data;
        uint16_t tag = 0;
        uint16_t msgtype;
        uint8_t *cursor;

        /* Sanity check */
        if (p9_handle == NULL || p9_handle->proto != PROTO_LIOP)
                return EINVAL;

	rc = p9c_getbuffer(p9_handle, &data, &tag);
	if (rc != 0)
		return rc;

	liop_initcursor(cursor, data->data, LIOP_TWRITE_RDMA_FINI, tag);
	p9_setvalue(cursor, reqid, uint64_t);
	p9_setmsglen(cursor, data);

	INFO_LOG(p9_handle->debug & P9_DEBUG_PROTO, "write rdma fini on reqid %"PRIx64, reqid);

	rc = p9c_sendrequest(p9_handle, data, tag);
	if (rc != 0)
		return rc;

	rc = p9c_getreply(p9_handle, &data, tag);
	if (rc != 0)
		return rc;

	cursor = data->data;
	liop_getheader(cursor, msgtype);
	switch (msgtype) {
		case LIOP_RWRITE_RDMA_FINI:
			p9_getvalue(cursor, rc, uint32_t);
			break;

		case LIOP_RERROR:
			p9_getvalue(cursor, rc, uint32_t);
			if (rc == 0) {
				ERROR_LOG("Got LIOP_ERROR but no rc set, msg %u/tag %u", LIOP_TWRITE_RDMA_FINI, tag);
				rc = EIO;
			}
			break;

		default:
			ERROR_LOG("Wrong reply type %u to msg %u/tag %u", msgtype, LIOP_TWRITE_RDMA_FINI, tag);
			rc = EIO;
	}

	p9c_putreply(p9_handle, data);

	return rc;
}
