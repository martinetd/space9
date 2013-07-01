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

#ifndef SPACE9
#define SPACE9

#include <stdint.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <dirent.h>     // MAXNAMLEN
#include <sys/param.h>  // MAXPATHLEN
#include <string.h>     // memset
#include <sys/types.h>
#include <sys/stat.h>


struct p9_handle;
struct p9_fid;
struct p9_qid;

#if HAVE_MOOSHIKA
#include <mooshika.h>
#else

/**
 * \struct msk_data
 * data size and content to send/just received
 */
typedef struct msk_data {
	uint32_t max_size; /**< size of the data field */
	uint32_t size; /**< size of the data to actually send/read */
	uint8_t *data; /**< opaque data */
	struct msk_data *next; /**< For recv/sends with multiple elements, used as a linked list */
	struct ibv_mr *mr;
} msk_data_t;

#endif

struct fs_stats {
	uint32_t type;
	uint32_t bsize;
	uint64_t blocks;
	uint64_t bfree;
	uint64_t bavail;
	uint64_t filse;
	uint64_t ffree;
	uint64_t fsid;
	uint32_t namelen;
};

/* 9P Magic Numbers */
#define P9_NOTAG	(uint16_t)(~0)
#define P9_NOFID	(uint32_t)(~0)
#define P9_NONUNAME	(uint32_t)(~0)
#define P9_MAXWELEM	16

/**
 * enum p9_qid - QID types
 * @P9_QTDIR: directory
 * @P9_QTAPPEND: append-only
 * @P9_QTEXCL: excluse use (only one open handle allowed)
 * @P9_QTMOUNT: mount points
 * @P9_QTAUTH: authentication file
 * @P9_QTTMP: non-backed-up files
 * @P9_QTSYMLINK: symbolic links (9P2000.u)
 * @P9_QTLINK: hard-link (9P2000.u)
 * @P9_QTFILE: normal files
 *
 * QID types are a subset of permissions - they are primarily
 * used to differentiate semantics for a file system entity via
 * a jump-table.  Their value is also the most signifigant 16 bits
 * of the permission_
 *
 * See Also: http://plan9.bell-labs.com/magic/man2html/2/sta
 */
enum {
	P9_QTDIR = 0x80,
	P9_QTAPPEND = 0x40,
	P9_QTEXCL = 0x20,
	P9_QTMOUNT = 0x10,
	P9_QTAUTH = 0x08,
	P9_QTTMP = 0x04,
	P9_QTSYMLINK = 0x02,
	P9_QTLINK = 0x01,
	P9_QTFILE = 0x00,
};

/**
 * @brief file system entity information
 *
 * qids are /identifiers used by 9P servers to track file system
 * entities.  The type is used to differentiate semantics for operations
 * on the entity (ie. read means something different on a directory than
 * on a file).  The path provides a server unique index for an entity
 * (roughly analogous to an inode number), while the version is updated
 * every time a file is modified and can be used to maintain cache
 * coherency between clients and serves.
 * Servers will often differentiate purely synthetic entities by setting
 * their version to 0, signaling that they should never be cached and
 * should be accessed synchronously.
 *
 * See Also://plan9.bell-labs.com/magic/man2html/2/sta
 */

typedef struct p9_qid {
	uint8_t type; /*< Type */
	uint32_t version; /*< Monotonically incrementing version number */
	uint64_t path; /*< Per-server-unique ID for a file system element */
} p9_qid_t;


/* library types */

struct p9_fid {
	struct p9_handle *p9_handle;
	uint32_t fid;
	uint64_t offset;
	char path[MAXPATHLEN];
	int pathlen;
	int openflags;
	struct p9_qid qid;
};


// 9p_core.c


/**
 * @brief Get a buffer to fill that will be ok to send directly
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [OUT]   pdata:	filled with appropriate buffer
 * @param [OUT]   tag:		available tag to use in the reply. If set to P9_NOTAG, this is taken instead.
 * @return 0 on success, errno value on error
 */
int p9c_getbuffer(struct p9_handle *p9_handle, msk_data_t **pdata, uint16_t *ptag);

/**
 * @brief Send a buffer obtained through getbuffer
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    data:		buffer to send
 * @param [IN]    tag:		tag to use
 * @return 0 on success, errno value on error
 */
int p9c_sendrequest(struct p9_handle *p9_handle, msk_data_t *data, uint16_t tag);

/**
 * @brief Put the buffer back in the list of available buffers for use
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    data:		buffer to put back
 * @param [IN]    tag:		tag to put back
 * @return 0 on success, errno value on error
 */
int p9c_abortrequest(struct p9_handle *p9_handle, msk_data_t *data, uint16_t tag);


/**
 * @brief Waits for a reply with a given tag to arrive
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [OUT]   pdata:	filled with appropriate buffer
 * @param [IN]    tag:		tag to wait for
 * @return 0 on success, errno value on error
 */
int p9c_getreply(struct p9_handle *p9_handle, msk_data_t **pdata, uint16_t tag);

/**
 * @brief Signal we're done with the buffer and it can be used again
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    data:		buffer to reuse
 * @return 0 on success, errno value on error
 */
int p9c_putreply(struct p9_handle *p9_handle, msk_data_t *data);

/**
 * @brief Get a fid structure ready to be used
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [OUT]   pfid:		fid to be filled
 * @return 0 on success, errno value on error
 */
int p9c_getfid(struct p9_handle *p9_handle, struct p9_fid **pfid);

/**
 * @brief Release a fid after clunk
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to release
 * @return 0 on success, errno value on error
 */
int p9c_putfid(struct p9_handle *p9_handle, struct p9_fid **pfid);

int p9c_reg_mr(struct p9_handle *p9_handle, msk_data_t *data);
int p9c_dereg_mr(struct p9_handle *p9_handle, msk_data_t *data);

// 9p_init.c

int p9_init(struct p9_handle **pp9_handle, char *conf_file);
void p9_destroy(struct p9_handle **pp9_handle);

// 9p_proto.c
#define P9_HDR_SIZE  4
#define P9_TYPE_SIZE 1
#define P9_TAG_SIZE  2
#define P9_STD_HDR_SIZE (P9_HDR_SIZE + P9_TYPE_SIZE + P9_TAG_SIZE)


/**
 * @brief Must be used first uppon connexion:
 * It is needed for client/server to agree on a msize, and to define the protocol version used (always "9P2000.L")
 *
 * This is done by default on init.
 *
 *
 * size[4] Tversion tag[2] msize[4] version[s]
 * size[4] Rversion tag[2] msize[4] version[s]
 *
 * @param [INOUT] p9_handle: used to define the msize, which value is updated on success.
 * @return 0 on success, errno value on error.
 */
int p9p_version(struct p9_handle *p9_handle);

/**
 * @brief Not implemented server side, would be used with p9_attach to setup an authentification
 *
 *
 * size[4] Tauth tag[2] afid[4] uname[s] aname[s] n_uname[4]
 * size[4] Rauth tag[2] aqid[13]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    uid:          uid to use
 * @param [IN]    pafid:	auth fid
 * @return 0 on success, errno value on error.
 */
int p9p_auth(struct p9_handle *p9_handle, uint32_t uid, struct p9_fid **pafid);

/**
 * @brief Attach a mount point for a given user
 * Not authentification yet.
 *
 * This is also done on init, the fid 0 is always populated.
 *
 *
 * size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s] n_uname[4]
 * size[4] Rattach tag[2] qid[13]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    uid:		uid to use
 * @param [OUT]   fid:		initial fid to populate
 * @return 0 on success, errno value on error.
 */
int p9p_attach(struct p9_handle *p9_handle, uint32_t uid, struct p9_fid **pfid);


/**
 * @brief Flush is used to invalidate a tag, if the reply isn't needed anymore.
 *
 *
 * size[4] Tflush tag[2] oldtag[2]
 * size[4] Rflush tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    oldtag:	the tag to invalidate
 * @return 0 on success, errno value on error.
 */
int p9p_flush(struct p9_handle *p9_handle, uint16_t oldtag);

/**
 * @brief Creates a new fid from path relative to a fid, or clone the said fid
 *
 *
 * size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
 * size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		existing fid to use
 * @param [IN]    path:		path to be based on. if NULL, clone the fid
 * @param [OUT]   pnewfid:	new fid to use
 * @return 0 on success, errno value on error.
 */
int p9p_walk(struct p9_handle *p9_handle, struct p9_fid *fid, char *path, struct p9_fid **pnewfid);

/* size[4] Rread tag[2] count[4] data[count] */
#define P9_ROOM_RREAD (P9_STD_HDR_SIZE + 4 )
/**
 * @brief zero-copy read from a file.
 * Even if count is > msize, more won't be received
 * There MUST be a finalize call to p9c_putreply(p9_handle, data) on success
 *
 * size[4] Tread tag[2] fid[4] offset[8] count[4]
 * size[4] Rread tag[2] count[4] data[count]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to use
 * @param [OUT]   zbuf:		data pointer here
 * @param [IN]    count:	count of bytes to read
 * @param [IN]    offset:	offset from which to read
 * @param [OUT]   pdata:	data to putreply
 * @return number of bytes read if >= 0, -errno on error.
 *          0 indicates eof?
 */
ssize_t p9pz_read(struct p9_handle *p9_handle, struct p9_fid *fid, char **zbuf, size_t count, uint64_t offset, msk_data_t **pdata);

/**
 * @brief Read from a file.
 * Even if count is > msize, more won't be received
 *
 *
 * size[4] Tread tag[2] fid[4] offset[8] count[4]
 * size[4] Rread tag[2] count[4] data[count]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to use
 * @param [OUT]   buf:		data is copied there.
 * @param [IN]    count:	count of bytes to read
 * @param [IN]    offset:	offset from which to read
 * @return number of bytes read if >= 0, -errno on error.
 *          0 indicates eof
 */
ssize_t p9p_read(struct p9_handle *p9_handle, struct p9_fid *fid, char *buf, size_t count, uint64_t offset);


/* size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count] */
#define P9_ROOM_TWRITE (P9_STD_HDR_SIZE + 4 + 8 + 4)
/**
 * @brief zero-copy write from a file.
 * Even if count is > msize, more won't be received
 * data MUST be registered with p9c_reg_mr(p9_handle, data) first
 *
 * size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
 * size[4] Rwrite tag[2] count[4]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to use
 * @param [IN]    data:		msk_registered msk_data pointer here
 * @param [IN]    offset:	offset from which to write
 * @return number of bytes written if >= 0, -errno on error.
 */
ssize_t p9pz_write(struct p9_handle *p9_handle, struct p9_fid *fid, msk_data_t *data, uint64_t offset);

/**
 * @brief Write to a file.
 * Even if count is > msize, more won't be written
 *
 *
 * size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
 * size[4] Rwrite tag[2] count[4]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to use
 * @param [IN]    buffer:	data to send
 * @param [IN]    count:	number of bytes to write
 * @param [IN]    offset:	offset from which to write
 * @return number of bytes written if >= 0, -errno on error
 */
ssize_t p9p_write(struct p9_handle *p9_handle, struct p9_fid *fid, char *buffer, size_t count, uint64_t offset);

/**
 * @brief Clunk a fid.
 * Note that even on error, the fid is no longer valid after a clunk.
 *
 *
 * size[4] Tclunk tag[2] fid[4]
 * size[4] Rclunk tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to clunk
 * @return 0 on success, errno value on error.
 */
int p9p_clunk(struct p9_handle *p9_handle, struct p9_fid **pfid);

/**
 * @brief Clunk a fid and unlinks the file associated with it.
 * Note that the fid is clunked even on error.
 *
 *
 * size[4] Tremove tag[2] fid[4]
 * size[4] Rremove tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to remove
 * @return 0 on success, errno value on error.
 */
int p9p_remove(struct p9_handle *p9_handle, struct p9_fid **pfid);

/**
 * @brief Get filesystem information.
 *
 *
 * size[4] Tstatfs tag[2] fid[4]
 * size[4] Rstatfs tag[2] type[4] bsize[4] blocks[8] bfree[8] bavail[8]
 *                        files[8] ffree[8] fsid[8] namelen[4]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		gets the stats of the filesystem this fid belongs to
 * @param [OUT]   fs_stats:	Filled with infos. Must be non-NULL.
 * @return 0 on success, errno value on error.
 */
int statfs(struct p9_handle *p9_handle, struct p9_fid *fid, struct fs_stats *fs_stats);

/**
 * @brief Open a file by its fid
 *
 *
 * size[4] Tlopen tag[2] fid[4] flags[4]
 * size[4] Rlopen tag[2] qid[13] iounit[4]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to open
 * @param [IN]    flags:	open flags as described in Linux open(2): O_RDONLY, O_RDWR, O_WRONLY, etc.
 * @param [OUT]   qid:		qid set if non-NULL
 * @param [OUT]   iounit:	iounit set if non-NULL. This is the maximum size for a single read or write if not 0.
 *                              FIXME: useless imo, we know the msize and can compute this as cleverly as the server.
 *                              currently, ganesha sets this to 0 anyway.
 * @return 0 on success, errno value on error.
 */
int p9p_lopen(struct p9_handle *p9_handle, struct p9_fid *fid, uint32_t flags, uint32_t *iounit);

/**
 * @brief Create a new file and open it.
 * This will fail if the file already exists.
 *
 *
 * size[4] Tlcreate tag[2] fid[4] name[s] flags[4] mode[4] gid[4]
 * size[4] Rlcreate tag[2] qid[13] iounit[4]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [INOUT] fid:		fid of the directory where to create the new file.
 *				Will be the created file's on success
 * @param [IN]    name:		name of the new file
 * @param [IN]    flags:	Linux kernel intent bits (e.g. O_RDONLY, O_WRONLY, O_RDWR)
 * @param [IN]    mode:		Linux creat(2) mode bits (e.g. 0640)
 * @param [IN]    gid:		effective gid
 * @param [OUT]   iounit:	iounit to set if non-NULL
 * @return 0 on success, errno value on error.
 */
int p9p_lcreate(struct p9_handle *p9_handle, struct p9_fid *fid, char *name, uint32_t flags, uint32_t mode,
               uint32_t gid, uint32_t *iounit);

#define P9_ROOM_TSYMLINK (P9_STD_HDR_SIZE + 4 + 2 + 2 + 4 )
/**
 * @brief Create a symlink
 *
 *
 * size[4] Tsymlink tag[2] dfid[4] name[s] symtgt[s] gid[4]
 * size[4] Rsymlink tag[2] qid[13]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    dfid:		fid of the directory where the new symlink will be created
 * @param [IN]    name:		name of the link
 * @param [IN]    symtgt:	link target
 * @param [IN]    gid:		effective gid
 * @param [OUT]   qid:		qid to fill if non-NULL
 * @return 0 on success, errno value on error.
 */
int p9p_symlink(struct p9_handle *p9_handle, struct p9_fid *dfid, char *name, char *symtgt, uint32_t gid,
               struct p9_qid *qid);

/**
 * @brief mknod.
 *
 *
 * size[4] Tmknod tag[2] dfid[4] name[s] mode[4] major[4] minor[4] gid[4]
 * size[4] Rmknod tag[2] qid[13]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    dfid:		fid of the directory where to create the node
 * @param [IN]    name:		name of the node
 * @param [IN]    mode:		Linux mknod(2) mode bits.
 * @param [IN]    major:	major number
 * @param [IN]    minor:	minor number
 * @param [IN]    gid:		effective gid
 * @param [OUT]   qid:		qid to fill if non-NULL
 * @return 0 on success, errno value on error.
 */
int p9p_mknod(struct p9_handle *p9_handle, struct p9_fid *dfid, char *name, uint32_t mode, uint32_t major, uint32_t minor,
             uint32_t gid, struct p9_qid *qid);

/**
 * @brief Move the file associated with fid
 *
 *
 * size[4] Trename tag[2] fid[4] dfid[4] name[s]
 * size[4] Rrename tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		source fid
 * @param [IN]    dfid:		destination directory
 * @param [IN]    name:		destination name
 * @return 0 on success, errno value on error.
 */
int p9p_rename(struct p9_handle *p9_handle, struct p9_fid *fid, struct p9_fid *dfid, char *name);

/**
 * @brief readlink.
 *
 *
 * size[4] Treadlink tag[2] fid[4]
 * size[4] Rreadlink tag[2] target[s]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid of the link
 * @param [OUT]   target:	content of the link
 * @param [IN]    size:		size of the target buffer
 * @return read size if >=0 on success (it was truncated if return value > size argument), -errno value on error.
 */
int p9pz_readlink(struct p9_handle *p9_handle, struct p9_fid *fid, char **ztarget, msk_data_t **pdata);
int p9p_readlink(struct p9_handle *p9_handle, struct p9_fid *fid, char *target, uint32_t size);

/* Bit values for getattr valid field. */
#define P9_GETATTR_MODE		0x00000001ULL
#define P9_GETATTR_NLINK	0x00000002ULL
#define P9_GETATTR_UID		0x00000004ULL
#define P9_GETATTR_GID		0x00000008ULL
#define P9_GETATTR_RDEV		0x00000010ULL
#define P9_GETATTR_ATIME	0x00000020ULL
#define P9_GETATTR_MTIME	0x00000040ULL
#define P9_GETATTR_CTIME	0x00000080ULL
#define P9_GETATTR_INO		0x00000100ULL
#define P9_GETATTR_SIZE		0x00000200ULL
#define P9_GETATTR_BLOCKS	0x00000400ULL

#define P9_GETATTR_BTIME	0x00000800ULL
#define P9_GETATTR_GEN		0x00001000ULL
#define P9_GETATTR_DATA_VERSION	0x00002000ULL

#define P9_GETATTR_BASIC	0x000007ffULL /* Mask for fields up to BLOCKS */
#define P9_GETATTR_ALL		0x00003fffULL /* Mask for All fields above */

struct p9_getattr {
	uint64_t valid;
	uint64_t ino; /* this actually comes from qid */
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint64_t nlink;
	uint64_t rdev;
	uint64_t size;
	uint64_t blksize;
	uint64_t blkcount;
	uint64_t atime_sec;
	uint64_t mtime_sec;
	uint64_t ctime_sec;
#if 0
	/* These all aren't used by the server */
	uint64_t atime_nsec;
	uint64_t mtime_nsec;
	uint64_t ctime_nsec;
	uint64_t btime_sec;
	uint64_t btime_nsec;
	uint64_t gen;
	uint64_t data_version;
#endif
};

/**
 * @brief getattr
 *
 *
 * size[4] Tgetattr tag[2] fid[4] request_mask[8]
 * size[4] Rgetattr tag[2] valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8]
 *                  rdev[8] size[8] blksize[8] blocks[8]
 *                  atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]
 *                  ctime_sec[8] ctime_nsec[8] btime_sec[8] btime_nsec[8]
 *                  gen[8] data_version[8]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param
 * @return 0 on success, errno value on error.
 */
int p9p_getattr(struct p9_handle *p9_handle, struct p9_fid *fid, struct p9_getattr *attr);

/* Bit values for setattr valid field from <linux/fs.h>. */
#define P9_SETATTR_MODE		0x00000001UL
#define P9_SETATTR_UID		0x00000002UL
#define P9_SETATTR_GID		0x00000004UL
#define P9_SETATTR_SIZE		0x00000008UL
#define P9_SETATTR_ATIME	0x00000010UL
#define P9_SETATTR_MTIME	0x00000020UL
#define P9_SETATTR_CTIME	0x00000040UL
#define P9_SETATTR_ATIME_SET	0x00000080UL
#define P9_SETATTR_MTIME_SET	0x00000100UL

struct p9_setattr {
	uint32_t valid;
	uint32_t mode;
	uint32_t uid;
	uint32_t gid;
	uint64_t size;
	uint64_t atime_sec;
	uint64_t mtime_sec;
#if 0
	/* unused by server */
	uint64_t atime_nsec;
	uint64_t mtime_nsec;
#endif
};

/**
 * @brief setattr
 *
 *
 * size[4] Tsetattr tag[2] fid[4] valid[4] mode[4] uid[4] gid[4] size[8]
 *                  atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]
 * size[4] Rsetattr tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param
 * @return 0 on success, errno value on error.
 */
int p9p_setattr(struct p9_handle *p9_handle, struct p9_fid *fid, struct p9_setattr *attr);

/**
 * @brief get a new fid to read/write given attr (or get the list)
 *
 *
 * Allocate a new fid to read the content of xattr name from fid
 * if name is NULL or empty, content will be the list of xattrs
 *
 * size[4] Txattrwalk tag[2] fid[4] newfid[4] name[s]
 * size[4] Rxattrwalk tag[2] size[8]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to clone
 * @param [OUT]   newfid:	newfid where xattr will be readable
 * @param [IN]    name:		name of xattr to read, or NULL for the list
 * @param [OUT]	  psize:	size available for reading
 * @return 0 on success, errno value on error.
 */
int p9p_xattrwalk(struct p9_handle *p9_handle, struct p9_fid *fid, struct p9_fid **pnewfid, char *name, uint64_t *psize);

/**
 * @brief change fid into xattr content
 *
 * Replace fid with one where xattr content will be writable
 *
 * size[4] Txattrcreate tag[2] fid[4] name[s] attr_size[8] flags[4]
 * size[4] Rxattrcreate tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to use
 * @param [IN]    name:		name of xattr to create
 * @param [IN]    size:		size of the xattr that will be written
 * @param [IN]    flags:	flags (derifed from linux setxattr flags: XATTR_CREATE, XATTR_REPLACE)
 * @return 0 on success, errno value on error.
 */
int p9p_xattrcreate(struct p9_handle *p9_handle, struct p9_fid *fid, char *name, uint64_t size, uint32_t flags);


/* size[4] Rreaddir tag[2] count[4] data[count] */
#define P9_ROOM_RREADDIR (P9_STD_HDR_SIZE + 4 )
typedef int (*p9p_readdir_cb) (void *arg, struct p9_handle *p9_handle, struct p9_fid *dfid, struct p9_qid *qid,
		uint8_t type, uint16_t namelen, char *name);
/**
 * @brief readdir with callback on each entry
 *
 *
 * size[4] Treaddir tag[2] fid[4] offset[8] count[4]
 * size[4] Rreaddir tag[2] count[4] data[count]
 *   data is: qid[13] offset[8] type[1] name[s]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		directory fid
 * @param [INOUT] offset:	offset to start from, will be set to where we left off on return
 * @param [IN]    callback:	callback to call for each entry.
 *                              processing stops if callback returns non-zero
 * @param [IN]    callback_arg:	user-provided callback arg
 * @return 0 on eod, number of entires read if positive, -errno value on error (or callback return value)
 */
int p9p_readdir(struct p9_handle *p9_handle, struct p9_fid *fid, uint64_t *offset, p9p_readdir_cb callback, void *callback_arg);

/**
 * @brief fsync
 *
 *
 * size[4] Tfsync tag[2] fid[4]
 * size[4] Rfsync tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to fsync
 * @return 0 on success, errno value on error.
 */
int p9p_fsync(struct p9_handle *p9_handle, struct p9_fid *fid);

/* Bit values for lock flags. */
#define P9_LOCK_FLAGS_BLOCK 1
#define P9_LOCK_FLAGS_RECLAIM 2

/**
 * @brief lock is used to acquire or release a POSIX record lock on fid and has semantics similar to Linux fcntl(F_SETLK).
 * start, length, and proc_id correspond to the analagous fields passed to Linux fcntl(F_SETLK) (man 2 fcntl)
 * flags bits are P9_LOCK_FLAGS_BLOCK (non-block without it) and RECLAIM (unused)
 *
 * client_id is set to the hostname by the engine
 *
 *
 * size[4] Tlock tag[2] fid[4] type[1] flags[4] start[8] length[8] proc_id[4] client_id[s]
 * size[4] Rlock tag[2] status[1]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to lock
 * @param [IN]    type:		lock type (F_RDLCK, F_WRLCK, F_UNLCK)
 * @param [IN]    flags:	flag bits are P9_LOCK_FLAGS_BLOCK or RECLAIM
 * @param [IN]    start:	Starting offset for lock
 * @param [IN]    length:	Number of bytes to lock
 * @param [IN]    proc_id:	PID of process blocking our lock
 * @return 0 on success, errno value on error. EACCESS on error, EAGAIN on lock held or grace period
 */
int p9p_lock(struct p9_handle *p9_handle, struct p9_fid *fid, uint8_t type, uint32_t flags, uint64_t start, uint64_t length, uint32_t proc_id);

/**
 * @brief getlock tests for the existence of a POSIX record lock and has semantics similar to Linux fcntl(F_GETLK).
 * As with lock, type has one of the values defined above, and start, length, and proc_id
 * correspond to the analagous fields in struct flock passed to Linux fcntl(F_GETLK).
 *
 * all values are pointers to values used and overwritten on success
 *
 * size[4] Tgetlock tag[2] fid[4] type[1] start[8] length[8] proc_id[4] client_id[s]
 * size[4] Rgetlock tag[2] type[1] start[8] length[8] proc_id[4] client_id[s]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		fid to get lock on
 * @param [IN]    ptype:	lock type (F_RDLCK, F_WRLCK, F_UNLCK)
 * @param [IN]    pstart:	Starting offset for lock
 * @param [IN]    plength:	Number of bytes to lock
 * @param [IN]    pproc_id:	PID of process blocking our lock
 * @return 0 on success, errno value on error.
 */
int p9p_getlock(struct p9_handle *p9_handle, struct p9_fid *fid, uint8_t *ptype, uint64_t *pstart, uint64_t *plength, uint32_t *pproc_id);

/**
 * @brief link
 *
 *
 * size[4] Tlink tag[2] dfid[4] fid[4] name[s]
 * size[4] Rlink tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    fid:		link target
 * @param [IN]    dfid:		fid of the directory where the new link will be created
 * @param [IN]    name:		name of the link
 * @return 0 on success, errno value on error.
 */
int p9p_link(struct p9_handle *p9_handle, struct p9_fid *fid, struct p9_fid *dfid, char *name);

/**
 * @brief mkdir
 *
 *
 * size[4] Tmkdir tag[2] dfid[4] name[s] mode[4] gid[4]
 * size[4] Rmkdir tag[2] qid[13]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    dfid:		fid of the directory where the new directory will be created
 * @param [IN]    name:		name of the link
 * @param [IN]    mode:		creation mode
 * @param [IN]    gid:		effective gid
 * @param [OUT]   qid:		qid to fill if non-NULL
 * @return 0 on success, errno value on error.
 */
int p9p_mkdir(struct p9_handle *p9_handle, struct p9_fid *dfid, char *name, uint32_t mode, uint32_t gid,
               struct p9_qid *qid);

/**
 * @brief renameat is preferred over rename
 *
 *
 * size[4] Trenameat tag[2] olddirfid[4] oldname[s] newdirfid[4] newname[s]
 * size[4] Rrenameat tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    dfid:		fid of the directory where file currently is
 * @param [IN]    name:		current filename
 * @param [IN]    newdfid:	fid of the directory to move into
 * @param [IN]    newname:	new filename
 * @return 0 on success, errno value on error.
 */
int p9p_renameat(struct p9_handle *p9_handle, struct p9_fid *dfid, char *name, struct p9_fid *newdfid, char *newname);

/**
 * @brief unlink file by name
 *
 *
 * size[4] Tunlinkat tag[2] dirfid[4] name[s] flags[4]
 * size[4] Runlinkat tag[2]
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    dfid:		fid of the directory where file currently is
 * @param [IN]    name:		name of file to unlink
 * @param [IN]    flags:	unlink flags, unused by server?
 * @return 0 on success, errno value on error.
 */
int p9p_unlinkat(struct p9_handle *p9_handle, struct p9_fid *dfid, char *name, uint32_t flags);



// 9p_libc.c

/**
 * @brief clunk
 *
 * @param [INOUT] pfid:		pointer to fid to clunk. will not clunk rootdir/cwd
 * @return 0 on success, errno value on error.
 */
int p9l_clunk(struct p9_fid **pfid);

/**
 * @brief walk that follows symlinks unless called with AT_SYMLINK_NOFOLLOW
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    dfid:		walk from there
 * @param [IN]    path:		path to walk to
 * @param [OUT]   pfid:		pointer to new fid
 * @param [IN]    flags:	0 or AT_SYMLINK_NOFOLLOW
 * @return 0 on success, errno value on error.
 */
int p9l_walk(struct p9_handle *p9_handle, struct p9_fid *dfid, char *path, struct p9_fid **pfid, int flags);

/**
 * @brief complex open by path call
 * Handles new file creation (if O_CREAT) and other flags (O_TRUNC, O_APPEND)
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file, relative from working directory, absolute from mount point
 * @param [OUT]   pfid:		pointer to new fid
 * @param [IN]    flags:	bitwise flag with O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND
 * @param [IN]    mode:		mode of new file if created. umask IS applied.
 * @param [IN]    gid:		gid of new file if created.
 * @return 0 on success, errno value on error.
 */
int p9l_open(struct p9_handle *p9_handle, char *path, struct p9_fid **pfid, uint32_t flags, uint32_t mode, uint32_t gid);

/**
 * @brief ls by path
 * opens directory given by path name and applies callback on each entry with custom arg
 * see examples in 9p_shell_functions.c
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		dir path (relative from cwd/absolute from mount point)
 * @param [IN]    cb:		callback function
 * @param [IN]    cb_arg:	callback custom arg
 * @return 0 on success, errno value on error.
 */
ssize_t p9l_ls(struct p9_handle *p9_handle, char *path, p9p_readdir_cb cb, void *cb_arg);

/**
 * @brief cd
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [path]  path:		new working directory path (relative from cwd, absolute from mount point)
 * @return 0 on success, errno value on error.
 */
int p9l_cd(struct p9_handle *p9_handle, char *path);

/**
 * @brief mv
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    src:		former file name
 * @param [IN]    dst:		new file name
 * @return 0 on success, errno value on error.
 */
int p9l_mv(struct p9_handle *p9_handle, char *src, char *dst);

/**
 * @brief rm AND rmdir - there is NO distinction!!!
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file to remove
 * @return 0 on success, errno value on error.
 */
int p9l_rm(struct p9_handle *p9_handle, char *path);

/**
 * @brief mkdir
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of new dir
 * @param [IN]    mode:		mode of new dir
 * @return 0 on success, errno value on error.
 */
int p9l_mkdir(struct p9_handle *p9_handle, char *path, uint32_t mode);

/**
 * @brief link by path
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    target:	link target path
 * @param [IN]    linkname:	link path
 * @return 0 on success, errno value on error.
 */
int p9l_link(struct p9_handle *p9_handle, char *target, char *linkname);

/**
 * @brief symlink
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    target:	symlink content
 * @param [IN]    linkname:	link path
 * @return 0 on success, errno value on error.
 */
int p9l_symlink(struct p9_handle *p9_handle, char *target, char *linkname);

/**
 * @brief umask
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    mask:		new umask
 * @return old umask
 */
int p9l_umask(struct p9_handle *p9_handle, uint32_t mask);

/**
 * @brief chown by path
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file to chown
 * @param [IN]    uid:		uid...
 * @param [IN]    gid:		gid...
 * @return 0 on success, errno value on error.
 */
int p9l_chown(struct p9_handle *p9_handle, char *path, uint32_t uid, uint32_t gid);

/**
 * @brief chmod by path
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file to chown
 * @param [IN]    mode:		mode...
 * @return 0 on success, errno value on error.
 */
int p9l_chmod(struct p9_handle *p9_handle, char *path, uint32_t mode);

/**
 * @brief stat by path
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file to stat
 * @param [INOUT] attr:		attr to fill, must NOT be null
 * @return 0 on success, errno value on error.
 */
int p9l_stat(struct p9_handle *p9_handle, char *path, struct p9_getattr *attr);

/**
 * @brief stat by path that doesn't follow symlinks
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file to stat
 * @param [INOUT] attr:		attr to fill, must NOT be null
 * @return 0 on success, errno value on error.
 */
int p9l_lstat(struct p9_handle *p9_handle, char *path, struct p9_getattr *attr);

/**
 * @brief xattrget by path
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file
 * @param [IN]    field:	attribute name. if "" or NULL, will return the list separated by \0s
 * @param [IN]    buf:		buffer where to store attributes
 * @param [IN]    count:	buffer size
 * @return size read on success, -errno value on error.
 */
ssize_t p9l_xattrget(struct p9_handle *p9_handle, char *path, char *field, char *buf, size_t count);

/**
 * @brief xattrlist - wrapper around xattrget with NULL field
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file
 * @param [IN]    buf:		buffer where to store attributes
 * @param [IN]    count:	buffer size
 * @return size read on success, -errno value on error.
 */
static inline ssize_t p9l_xattrlist(struct p9_handle *p9_handle, char *path, char *buf, size_t count) {
	return p9l_xattrget(p9_handle, path, NULL, buf, count);
}


/**
 * @brief xattrset by path
 *
 * @param [IN]    p9_handle:	connection handle
 * @param [IN]    path:		path of file
 * @param [IN]    field:	field to define
 * @param [IN]    buf:		buffer to copy from. if empty, the attribute is removed
 * @param [IN]    count:	number of bytes to copy
 * @param [IN]    flags:	flag can be 0 (do it anyway), XATTR_CREATE (fail if exist)
 *				or XATTR_REPLACE (fail if doesn't exist)
 * @return size written on success, -errno value on error.
 */
ssize_t p9l_xattrset(struct p9_handle *p9_handle, char *path, char *field, char *buf, size_t count, int flags);


/**
 * @brief fstatat
 *
 * @param [IN]    dfid:		fid of a directory
 * @param [IN]    path:		path of file in dir
 * @param [IN]    flags:	0 or AT_SYMLINK_NOFOLLOW
 * @return 0 on success, errno value on error.
 */
int p9l_fstatat(struct p9_fid *dfid, char *path, struct p9_getattr *attr, int flags);

/**
 * @brief xattrget by fid
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    field:        attribute name. if "" or NULL, will return the list separated by \0s
 * @param [IN]    buf:          buffer where to store attributes
 * @param [IN]    count:        buffer size
 * @return size read on success, -errno value on error.
 */
ssize_t p9l_fxattrget(struct p9_fid *fid, char *field, char *buf, size_t count);

/**
 * @brief xattrlist by fid - wrapper around xattrget with NULL field
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    buf:          buffer where to store attributes
 * @param [IN]    count:        buffer size
 * @return size read on success, -errno value on error.
 */
static inline ssize_t p9l_fxattrlist(struct p9_fid *fid, char *buf, size_t count) {
	return p9l_fxattrget(fid, NULL, buf, count);
}

/**
 * @brief xattrset by fid
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    buf:          buffer to copy from. if empty, the attribute is removed
 * @param [IN]    count:        number of bytes to copy
 * @param [IN]    flags:        flag can be 0 (do it anyway), XATTR_CREATE (fail if exist)
 *                              or XATTR_REPLACE (fail if doesn't exist)
 * @return size written on success, -errno value on error.
 */
ssize_t p9l_fxattrset(struct p9_fid *fid, char *field, char *buf, size_t count, int flags);


/**
 * @brief chown by fid
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    uid:		uid...
 * @param [IN]    gid:		gid...
 * @return 0 on success, errno value on error.
 */
static inline int p9l_fchown(struct p9_fid *fid, uint32_t uid, uint32_t gid) {
	struct p9_setattr attr;
	memset(&attr, 0, sizeof(struct p9_setattr));
	attr.valid = P9_SETATTR_UID | P9_SETATTR_GID;
	attr.uid = uid;
	attr.gid = gid;
	return p9p_setattr(fid->p9_handle, fid, &attr);
}

/**
 * @brief chmod by fid
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    mode:		mode
 * @return 0 on success, errno value on error.
 */
static inline int p9l_fchmod(struct p9_fid *fid, uint32_t mode) {
	struct p9_setattr attr;
	memset(&attr, 0, sizeof(struct p9_setattr));
	attr.valid = P9_SETATTR_MODE;
	attr.mode = mode;
	return p9p_setattr(fid->p9_handle, fid, &attr);
}

/**
 * @brief stat by fid
 *
 * @param [IN]    fid:		fid to use
 * @param [INOUT] attr:		attribute to fill, must NOT be NULL.
 * @return 0 on success, errno value on error.
 */
static inline int p9l_fstat(struct p9_fid *fid, struct p9_getattr *attr) {
	return p9p_getattr(fid->p9_handle, fid, attr);
}

/**
 * @brief fsync
 *
 * @param [IN]    fid:		fid to use
 * @return 0 on success, errno value on error.
 */
static inline int p9l_fsync(struct p9_fid *fid) {
	return p9p_fsync(fid->p9_handle, fid);
}


/**
 * @brief fseek into a file
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    offset:	offset...
 * @param [IN]    whence:	SEEK_SET, SEEK_END or SEEK_CUR, cf. man fseek(3)
 * @return 0 on success, errno value on error.
 */
int p9l_fseek(struct p9_fid *fid, int64_t offset, int whence);

/**
 * @brief get current offset
 * same as fid->offset
 *
 * @param [IN]    fid:		fid to use
 * @return 0 on success, errno value on error.
 */
static inline uint64_t p9l_ftell(struct p9_fid *fid) {
	return fid->offset;
}

/**
 * @brief write stuff!
 * If buffer is small it copies it, if it's big enough register memories and sends it zerocopy
 * It does the looping for you, so if return value < count we got a problem.
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    buffer:	buffer to send
 * @param [IN]    count:	size of buffer
 * @return size written on success, -errno value on error.
 */
ssize_t p9l_write(struct p9_fid *fid, char *buffer, size_t count);

/**
 * @brief writev
 * iterates around write for each iov.
 * Someday might register small vectors together to have one bigger write,
 * but mem registration is expensive so might not be worth it.
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    iov:		iov array
 * @param [IN]    iovcnt:	number of iovs
 * @return size written on success, -errno value on error.
 */
ssize_t p9l_writev(struct p9_fid *fid, struct iovec *iov, int iovcnt);

/**
 * @brief read stuff!
 * There is a copy anyway, unfortnately.
 * It does the looping for you, so if return value < count we got eof.
 * Might add a flag later to change that as it's not necessarily what we want
 * (e.g. stop as soon as p9p_read gives us less than the count we asked for)
 * Shouldn't change much given we only consider real files and not sockets/blocking stuff though.
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    buffer:	buffer to fill
 * @param [IN]    count:	size of buffer
 * @return size read on success, -errno value on error.
 */
ssize_t p9l_read(struct p9_fid *fid, char *buffer, size_t count);

/**
 * @brief readv
 * just a loop around read really.
 *
 * @param [IN]    fid:		fid to use
 * @param [IN]    iov:		iov array
 * @param [IN]    iovcnt:	number of iovs
 * @return size read on success, -errno value on error.
 */
ssize_t p9l_readv(struct p9_fid *fid, struct iovec *iov, int iovcnt);



// 9p_shell_functions.c - used for python bindings... or not, but can't hurt to keep them here for now
int p9s_ls(struct p9_handle *p9_handle, char *arg);
int p9s_cd(struct p9_handle *p9_handle, char *arg);
int p9s_cat(struct p9_handle *p9_handle, char *arg);
int p9s_mkdir(struct p9_handle *p9_handle, char *arg);
int p9s_pwd(struct p9_handle *p9_handle, char *arg);
int p9s_xwrite(struct p9_handle *p9_handle, char *arg);
int p9s_rm(struct p9_handle *p9_handle, char *arg);
int p9s_mv(struct p9_handle *p9_handle, char *arg);
int p9s_ln(struct p9_handle *p9_handle, char *arg);


#endif
