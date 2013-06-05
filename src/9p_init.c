#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>      // gethostbyname
#include <sys/socket.h> // gethostbyname
#include <mooshika.h>
#include "9p.h"
#include "9p_proto.h"
#include "utils.h"
#include "settings.h"

struct p9_conf {
	char aname[MAXPATHLEN];
	char uname[MAXNAMLEN];
	uint32_t uid;
	uint32_t recv_num;
	uint32_t max_fid;
	uint32_t max_tag;
	uint32_t msize;
	struct msk_trans_attr trans_attr;
};

enum conftype { 
	INT,
	UINT,
	IP,
	IP6,
	PORT,
	PORT6,
	STRING,
	SIZE
};

struct conf { char *token; enum conftype type; int offset; };

#define offsetof(type, member)  __builtin_offsetof (type, member)

static struct conf conf_array[] = {
	{ "server", IP, 0 },
	{ "port", PORT, 0 },
	{ "server6", IP6, 0 },
	{ "port6", PORT6, 0 },
	{ "debug", UINT, offsetof(struct p9_conf, trans_attr) + offsetof(struct msk_trans_attr, debug) },
	{ "msize", SIZE, offsetof(struct p9_conf, msize) },
	{ "recv_num", UINT, offsetof(struct p9_conf, trans_attr) + offsetof(struct msk_trans_attr, rq_depth)  },
	{ "rq_depth", UINT, offsetof(struct p9_conf, trans_attr) + offsetof(struct msk_trans_attr, rq_depth) },
	{ "sq_depth", UINT, offsetof(struct p9_conf, trans_attr) + offsetof(struct msk_trans_attr, sq_depth) },
	{ "aname", STRING, offsetof(struct p9_conf, aname) },
	{ "uname", STRING, offsetof(struct p9_conf, uname) },
	{ "uid", UINT, offsetof(struct p9_conf, uid) },
	{ "max_fid", UINT, offsetof(struct p9_conf, uid) },
	{ "max_tag", UINT, offsetof(struct p9_conf, uid) },
	{ NULL, 0, 0 }
};

int parser(char *conf_file, struct p9_conf *p9_conf) {
	FILE *fd;
	char line[2*MAXPATHLEN];
	int i, ret;
	struct hostent *host;
	char buf_s[MAXNAMLEN];
	int buf_i;
	void *ptr;

	fd = fopen(conf_file, "r");

	if (fd == NULL) {
		i = errno;
		ERROR_LOG("Could not open %s: %s (%d)", conf_file, strerror(i), i);
		return i;
	}

	// fill default values.
	memset(p9_conf, 0, sizeof(struct p9_conf));
	p9_conf->trans_attr.server = -1;
	p9_conf->trans_attr.disconnect_callback = p9_disconnect_cb;
	p9_conf->trans_attr.rq_depth = DEFAULT_RECV_NUM;
	p9_conf->msize = DEFAULT_MSIZE;
	p9_conf->max_fid = DEFAULT_MAX_FID;
	p9_conf->max_tag = DEFAULT_MAX_TAG;

	while (fgets(line, 2*MAXPATHLEN, fd)) {
		// skip comments
		if (line[0] == '#' || line[0] == '\n')
			continue;

		for (i=0; conf_array[i].token != NULL; i++) {
			if (strncmp(conf_array[i].token, line, strlen(conf_array[i].token)))
				continue;

			// we have a match
			switch(conf_array[i].type) {
				case UINT:
					ptr = (char*)p9_conf + conf_array[i].offset;
					if (sscanf(line, "%*s = %u", (int*)ptr) != 1) {
						ERROR_LOG("scanf error on line: %s", line);
						return EINVAL;
					}
					INFO_LOG(p9_conf->trans_attr.debug, "Read %s: %i", conf_array[i].token, *(int*)ptr);
					break;
				case STRING:
					ptr = (char*)p9_conf + conf_array[i].offset;
					if (sscanf(line, "%*s = %s", (char*)ptr) != 1) {
						ERROR_LOG("scanf error on line: %s", line);
						return EINVAL;
					}
					INFO_LOG(p9_conf->trans_attr.debug, "Read %s: %s", conf_array[i].token, (char*)ptr);
					break;
				case SIZE:
					ptr = (char*)p9_conf + conf_array[i].offset;
					ret = sscanf(line, "%*s = %i %[a-zA-Z] %i", (int*)ptr, buf_s, &buf_i);
					if (ret >= 2) {
						if (set_size((int*)ptr, buf_s))
							return EINVAL;
						if (ret == 3)
							*(int*)ptr += buf_i;
					} else if (ret != 1) {
						ERROR_LOG("scanf error on line: %s", line);
						return EINVAL;
					}
					INFO_LOG(p9_conf->trans_attr.debug, "Read %s: %i", conf_array[i].token, *(int*)ptr);
					break;
				case IP:
					if (sscanf(line, "%*s = %s", buf_s) != 1) {
						ERROR_LOG("scanf error on line: %s", line);
						return EINVAL;
					}
					host = gethostbyname(buf_s);
					//FIXME: if (host->h_addrtype == AF_INET6) {
					p9_conf->trans_attr.addr.sa_in.sin_family = AF_INET;
					memcpy(&p9_conf->trans_attr.addr.sa_in.sin_addr, host->h_addr_list[0], 4);

					// Sanity check: we got an IP
					p9_conf->trans_attr.server = 0;

					// Default port. depends on the sin family
					((struct sockaddr_in*) &p9_conf->trans_attr.addr)->sin_port = htons(DEFAULT_PORT);

					INFO_LOG(p9_conf->trans_attr.debug, "Read %s: %s", conf_array[i].token, buf_s);
					break;
				case PORT:
					if (sscanf(line, "%*s = %i", &buf_i) != 1) {
						ERROR_LOG("scanf error on line: %s", line);
						return EINVAL;
					}
					((struct sockaddr_in*) &p9_conf->trans_attr.addr)->sin_port = htons(buf_i);
					INFO_LOG(p9_conf->trans_attr.debug, "Read %s: %i", conf_array[i].token, buf_i);
					break;
				default:
					ERROR_LOG("token %s not yet implemented", conf_array[i].token);
			}
			break;
		}

		// no match found
		if (conf_array[i].token == NULL) {
			ERROR_LOG("Unknown configuration entry: %s", line);
		}
	}

	return 0;	
}

void p9_destroy(struct p9_handle **pp9_handle) {
	struct p9_handle *p9_handle = *pp9_handle;
	if (p9_handle) {
		if (p9_handle->fids_bitmap) {
			free(p9_handle->fids_bitmap);
			p9_handle->fids_bitmap = NULL;
		}
		if (p9_handle->tags_bitmap) {
			free(p9_handle->tags_bitmap);
			p9_handle->tags_bitmap = NULL;
		}
		if (p9_handle->fids_bucket) {
			bucket_destroy(p9_handle->fids_bucket);
			p9_handle->fids_bucket = NULL;
		}
		if (p9_handle->tags) {
			free(p9_handle->tags);
			p9_handle->tags = NULL;
		}
		if (p9_handle->wdata) {
			free(p9_handle->wdata);
			p9_handle->wdata = NULL;
		}
		if (p9_handle->rdata) {
			free(p9_handle->rdata);
			p9_handle->rdata = NULL;
		}
		if (p9_handle->mr) {
			msk_dereg_mr(p9_handle->mr);
			p9_handle->mr = NULL;
		}
		if (p9_handle->rdmabuf) {
			free(p9_handle->rdmabuf);
			p9_handle->rdmabuf = NULL;
		}
	}
}

int p9_init(struct p9_handle **pp9_handle, char *conf_file) {
	struct p9_conf p9_conf;
	struct p9_handle *p9_handle;
	int i, rc;

	rc = parser("sample.conf", &p9_conf);
	if (rc) {
		ERROR_LOG("parsing error");
		return rc;
	}
	if (p9_conf.aname[0] == '\0' || p9_conf.trans_attr.server == -1) {
		ERROR_LOG("You need to set at least aname and server");
		return EINVAL;
	}

	p9_handle = malloc(sizeof(struct p9_handle));
	if (p9_handle == NULL) {
		ERROR_LOG("Could not allocate p9_handle");
		return ENOMEM;
	}

	do {
		strcpy(p9_handle->aname, p9_conf.aname);

		/** @todo if (p9_conf.uname) p9_handle->uid = uidofuname(p9_conf.uname) */
		p9_handle->debug = p9_conf.trans_attr.debug;
		p9_handle->uid = p9_conf.uid;
		p9_handle->recv_num = p9_conf.trans_attr.rq_depth;
		p9_handle->msize = p9_conf.msize;
		p9_handle->max_fid = p9_conf.max_fid;
		p9_handle->max_tag = (p9_conf.max_tag > 65535 ? 65535 : p9_conf.max_tag);

		rc = msk_init(&p9_handle->trans, &p9_conf.trans_attr);
		if (rc) {
			ERROR_LOG("msk_init failed: %s (%d)", strerror(rc), rc);
			break;
		}

		p9_handle->trans->private_data = p9_handle;

		rc = msk_connect(p9_handle->trans);
		if (rc) {
			ERROR_LOG("msk_connect failed: %s (%d)", strerror(rc), rc);
			break;
		}

		// alloc buffers, post receive buffers
		p9_handle->rdmabuf = malloc(2 * p9_handle->recv_num * p9_conf.msize);
		p9_handle->rdata = malloc(p9_handle->recv_num * sizeof(msk_data_t));
		p9_handle->wdata = malloc(p9_handle->recv_num * sizeof(msk_data_t));
		if (p9_handle->rdmabuf == NULL || p9_handle->rdata == NULL || p9_handle->wdata == NULL) {
			ERROR_LOG("Could not allocate data buffer (%luMB)",
			          2 * p9_handle->recv_num * (p9_conf.msize + sizeof(msk_data_t)) / 1024 / 1024);
			rc = ENOMEM;
			break;
		}

		p9_handle->mr = msk_reg_mr(p9_handle->trans, p9_handle->rdmabuf, 2 * p9_handle->recv_num * p9_conf.msize, IBV_ACCESS_LOCAL_WRITE);
		if (p9_handle->mr == NULL) {
			ERROR_LOG("Could not register memory buffer");
			rc = EIO;
			break;
		}

		for (i=0; i < p9_handle->recv_num; i++) {
			p9_handle->rdata[i].data = p9_handle->rdmabuf + i * p9_conf.msize;
			p9_handle->wdata[i].data = p9_handle->rdata[i].data + p9_handle->recv_num * p9_conf.msize;
			p9_handle->rdata[i].size = p9_handle->rdata[i].max_size = p9_handle->wdata[i].max_size = p9_conf.msize;
			rc = msk_post_recv(p9_handle->trans, &p9_handle->rdata[i], p9_handle->mr, p9_recv_cb, p9_recv_err_cb, NULL);
			if (rc) {
				ERROR_LOG("Could not post recv buffer %i: %s (%d)", i, strerror(rc), rc);
				rc = EIO;
				break;
			}
		}
		if (rc)
			break;

		 /* bitmaps, divide by /8 (=/64*8)*/
		p9_handle->wdata_bitmap = malloc(p9_handle->recv_num/8 + (p9_handle->recv_num % 8 == 0 ? 0 : 1));
		p9_handle->fids_bitmap = malloc(p9_handle->max_fid/8 + (p9_handle->max_fid % 8 == 0 ? 0 : 1));
		p9_handle->tags_bitmap = malloc(p9_handle->max_tag/8 + (p9_handle->max_tag % 8 == 0 ? 0 : 1));
		p9_handle->fids_bucket = bucket_init(p9_handle->max_tag/8, sizeof(struct p9_tag));
		p9_handle->tags = malloc(p9_handle->max_fid * sizeof(struct p9_fid));
		if (p9_handle->wdata_bitmap == NULL ||
		    p9_handle->fids_bitmap == NULL || p9_handle->tags_bitmap == NULL ||
		    p9_handle->fids_bucket == NULL || p9_handle->tags == NULL) {
			rc = ENOMEM;
			break;
		}

		memset(p9_handle->wdata_bitmap, 0, p9_handle->recv_num/8 + (p9_handle->recv_num % 8 == 0 ? 0 : 1));
		memset(p9_handle->fids_bitmap, 0, p9_handle->max_fid/8 + (p9_handle->max_fid % 8 == 0 ? 0 : 1));
		memset(p9_handle->tags_bitmap, 0, p9_handle->max_tag/8 + (p9_handle->max_tag % 8 == 0 ? 0 : 1));
		memset(p9_handle->tags, 0, p9_handle->max_fid * sizeof(struct p9_fid));

		pthread_mutex_init(&p9_handle->wdata_lock, NULL);
		pthread_cond_init(&p9_handle->wdata_cond, NULL);
		pthread_mutex_init(&p9_handle->recv_lock, NULL);
		pthread_cond_init(&p9_handle->recv_cond, NULL);
		pthread_mutex_init(&p9_handle->tag_lock, NULL);
		pthread_cond_init(&p9_handle->tag_cond, NULL);
		pthread_mutex_init(&p9_handle->fid_lock, NULL);
		pthread_cond_init(&p9_handle->fid_cond, NULL);

		rc = msk_finalize_connect(p9_handle->trans);
		if (rc)
			break;

		rc = p9_version(p9_handle);
		if (rc)
			break;

		rc = p9_attach(p9_handle, p9_conf.uid, &p9_handle->root_fid);
		if (rc)
			break;
	} while (0);

	if (rc) {
		p9_destroy(&p9_handle);
		return rc;
	}

	*pp9_handle = p9_handle;
	return 0;
}