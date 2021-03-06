
#ifndef P9_INTERNALS
#define P9_INTERNALS

#include <stdlib.h>
#include "space9.h"
#include "bitmap.h"
#include "bucket.h"

#if HAVE_MOOSHIKA
#else

#define IBV_ACCESS_LOCAL_WRITE 1

typedef union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_int6;
	struct sockaddr_storage sa_stor;
} sockaddr_union_t;

typedef struct msk_ctx msk_ctx_t;
typedef struct msk_trans_attr msk_trans_attr_t;
typedef struct msk_trans msk_trans_t;
typedef void (*ctx_callback_t)(msk_trans_t *trans, msk_data_t *data, void *arg);
typedef void (*disconnect_callback_t) (msk_trans_t *trans);

struct msk_stats {
	uint64_t rx_bytes;
	uint64_t rx_pkt;
	uint64_t tx_bytes;
	uint64_t tx_pkt;
	uint64_t err;
	/* timespecs only used debug has MSK_DEBUG_SPEED */
	struct timespec time_callback;
	struct timespec time_compevent;
};

enum ibv_qp_type {
	IBV_QPT_RC = 2,
	IBV_QPT_UC,
	IBV_QPT_UD
};

struct ibv_qp_cap {
	uint32_t		max_send_wr;
	uint32_t		max_recv_wr;
	uint32_t		max_send_sge;
	uint32_t		max_recv_sge;
	uint32_t       		max_inline_data;
};

struct ibv_qp_init_attr	{
	void		       *qp_context;
	struct ibv_cq	       *send_cq;
	struct ibv_cq	       *recv_cq;
	struct ibv_srq	       *srq;
	struct ibv_qp_cap	cap;
	enum ibv_qp_type	qp_type;
	int			sq_sig_all;
};

/**
 * \struct msk_trans
 * RDMA transport instance
 */
struct msk_trans {
	enum msk_state {
		MSK_INIT,
		MSK_LISTENING,
		MSK_ADDR_RESOLVED,
		MSK_ROUTE_RESOLVED,
		MSK_CONNECT_REQUEST,
		MSK_CONNECTED,
		MSK_CLOSING,
		MSK_CLOSED,
		MSK_ERROR
	} state;			/**< tracks the transport state machine for connection setup and tear down */
	struct rdma_cm_id *cm_id;	/**< The RDMA CM ID */
	struct rdma_event_channel *event_channel;
	struct ibv_comp_channel *comp_channel;
	struct ibv_pd *pd;		/**< Protection Domain pointer */
	struct ibv_qp *qp;		/**< Queue Pair pointer */
	struct ibv_cq *cq;		/**< Completion Queue pointer */
	disconnect_callback_t disconnect_callback;
	void *private_data;
	long timeout;			/**< Number of mSecs to wait for connection management events */
	struct ibv_qp_init_attr qp_attr;
	char *node;			/**< The remote peer's hostname */
	char *port;			/**< The service port (or name) */
	int conn_type;			/**< RDMA Port space, probably RDMA_PS_TCP */
	int server;			/**< 0 if client, number of connections to accept on server, -1 (MSK_SERVER_CHILD) if server's accepted connection */
	int destroy_on_disconnect;      /**< set to 1 if mooshika should perform cleanup */
	uint32_t debug;
	struct rdma_cm_id **conn_requests; /**< temporary child cm_id, only used for server */
	msk_ctx_t *send_buf;		/**< pointer to actual context data */
	msk_ctx_t *recv_buf;		/**< pointer to actual context data */
	pthread_mutex_t ctx_lock;	/**< lock for contexts */
	pthread_cond_t ctx_cond;	/**< cond for contexts */
	pthread_mutex_t cm_lock;	/**< lock for connection events */
	pthread_cond_t cm_cond;		/**< cond for connection events */
	struct ibv_recv_wr *bad_recv_wr;
	struct ibv_send_wr *bad_send_wr;
	struct msk_stats stats;
	char *stats_prefix;
	int stats_sock;
};

struct msk_trans_attr {
	disconnect_callback_t disconnect_callback;
	int debug;			/**< verbose output to stderr if set */
	int server;			/**< 0 if client, number of connections to accept on server */
	int destroy_on_disconnect;      /**< set to 1 if mooshika should perform cleanup */
	long timeout;			/**< Number of mSecs to wait for connection management events */
	int sq_depth;			/**< The depth of the Send Queue */
	int max_send_sge;		/**< Maximum number of s/g elements per send */
	int rq_depth;			/**< The depth of the Receive Queue. */
	int max_recv_sge;		/**< Maximum number of s/g elements per recv */
	int worker_count;		/**< Number of worker threads - works only for the first init */
	int worker_queue_size;		/**< Size of the worker data queue - works only for the first init */
	int conn_type;			/**< RDMA Port space, probably RDMA_PS_TCP */
	char *node;			/**< The remote peer's hostname */
	char *port;			/**< The service port (or name) */
	struct ibv_pd *pd;		/**< Protection Domain pointer */
	char *stats_prefix;
};


/**
 * \struct msk_rloc
 * stores one remote address to write/read at
 */
typedef struct msk_rloc {
	uint64_t raddr; /**< remote memory address */
	uint32_t rkey; /**< remote key */
	uint32_t size; /**< size of the region we can write/read */
} msk_rloc_t;

#endif

/* 9p-specific types */

/**
 * @brief Length prefixed string type
 *
 * The protocol uses length prefixed strings for all
 * string data, so we replicate that for our internal
 * string members.
 */

struct p9_str {
	uint16_t  len; /*< Length of the string */
	char *str; /*< The string */
};


static inline void p9_get_tag(uint16_t *ptag, uint8_t *data) {
	memcpy(ptag, data + sizeof(uint32_t) /* msg len */ + sizeof(uint8_t) /* msg type */, sizeof(uint16_t));
}

struct p9_tag {
	msk_data_t *rdata;
	uint32_t wdata_i;
};

struct p9_net_ops {
	int (*init)(msk_trans_t **ptrans, msk_trans_attr_t *attr);
	void (*destroy_trans)(msk_trans_t **ptrans);

	int (*connect)(msk_trans_t *trans);
	int (*finalize_connect)(msk_trans_t *trans);

	struct ibv_mr *(*reg_mr)(msk_trans_t *trans, void *memaddr, size_t size, int access);
	int (*dereg_mr)(struct ibv_mr *mr);

	int (*post_n_recv)(msk_trans_t *trans, msk_data_t *data, int num_sge, ctx_callback_t callback, ctx_callback_t err_callback, void *callback_arg);
	int (*post_n_send)(msk_trans_t *trans, msk_data_t *data, int num_sge, ctx_callback_t callback, ctx_callback_t err_callback, void *callback_arg);
};

struct p9_handle {
	uint16_t max_tag;
	uint16_t aname_len;
	char aname[MAXPATHLEN];
	char hostname[MAX_CANON+1];
	uint8_t *rdmabuf;
	struct p9_net_ops *net_ops;
	msk_trans_t *trans;
	msk_data_t *rdata;
	msk_data_t *wdata;
	pthread_mutex_t wdata_lock;
	pthread_cond_t wdata_cond;
	pthread_mutex_t recv_lock;
	pthread_cond_t recv_cond;
	pthread_mutex_t tag_lock;
	pthread_cond_t tag_cond;
	pthread_mutex_t fid_lock;
	pthread_mutex_t connection_lock;
	pthread_mutex_t credit_lock;
	pthread_cond_t credit_cond;
	uint32_t credits;
	uint32_t max_fid;
	bitmap_t *wdata_bitmap;
	bitmap_t *tags_bitmap;
	struct p9_tag *tags;
	bitmap_t *fids_bitmap;
	bucket_t *fids_bucket;
	struct p9_fid **fids;
	uint32_t uid;
	uint32_t recv_num;
	uint32_t msize;
	uint32_t debug;
	uint32_t umask;
	uint32_t pipeline;
	struct p9_fid *root_fid;
	struct p9_fid *cwd;
	struct msk_trans_attr trans_attr;
};


// 9p_callbacks.c

void p9_disconnect_cb(msk_trans_t *trans);

void p9_recv_err_cb(msk_trans_t *trans, msk_data_t *data, void *arg);
void p9_recv_cb(msk_trans_t *trans, msk_data_t *data, void *arg);
void p9_send_cb(msk_trans_t *trans, msk_data_t *data, void *arg);
void p9_send_err_cb(msk_trans_t *trans, msk_data_t *data, void *arg);


/* utility flags - kernel O_RDONLY sucks for being 0 */
#define RDFLAG 1
#define WRFLAG 2



// 9p_proto.c
/**
 * @brief walk without allocating a new fid
 *
 * @param[in]    p9_handle:	connection handle
 * @param[in]    fid:		directory fid
 * @param[in]    path:		path to walk
 * @param[in]    newfid_i:	new fid number
 * @return 0 on success, errno value on error
 */
int p9p_rewalk(struct p9_handle *p9_handle, struct p9_fid *fid, char *path, uint32_t newfid_i);

ssize_t p9pz_write_send(struct p9_handle *p9_handle, struct p9_fid *fid, msk_data_t *data, uint64_t offset, uint16_t *ptag);
ssize_t p9pz_write_wait(struct p9_handle *p9_handle, uint16_t tag);
ssize_t p9p_write_send(struct p9_handle *p9_handle, struct p9_fid *fid, char *buf, size_t count, uint64_t offset, uint16_t *ptag);
ssize_t p9p_write_wait(struct p9_handle *p9_handle, uint16_t tag);
ssize_t p9pz_read_send(struct p9_handle *p9_handle, struct p9_fid *fid, size_t count, uint64_t offset, uint16_t *ptag);
ssize_t p9pz_read_wait(struct p9_handle *p9_handle, msk_data_t **pdata, uint16_t tag);

static inline uint32_t p9p_write_len(struct p9_handle *p9_handle, uint32_t count) {
	if (count > p9_handle->msize - P9_ROOM_TWRITE)
		count = p9_handle->msize - P9_ROOM_TWRITE;
	/* align IO if possible */
	if (count > 1024*1024 && count < 1025*1024)
		count = 1024*1024;
	return count;
}

static inline uint32_t p9p_read_len(struct p9_handle *p9_handle, uint32_t count) {
	if (count > p9_handle->msize - P9_ROOM_RREAD)
		count = p9_handle->msize - P9_ROOM_RREAD;
	/* align IO if possible */
	if (count > 1024*1024 && count < 1025*1024)
		count = 1024*1024;
	return count;
}


#endif
