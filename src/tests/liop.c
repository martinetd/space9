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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <getopt.h>

#include "space9.h"
#include "utils.h" // logs

#include "../9p_internals.h"

#include "bucket.h"

#define DEFAULT_CONFFILE "../sample.conf"
#define DEFAULT_SERVER "127.0.0.1"

void print_help(char **argv) {
        printf("Usage: %s [-c conf] [-s startpoint] [-t thread-num]\n", argv[0]);
        printf( "Optional arguments:\n"
                "       -c, --conf file: conf file to use\n"
                "       -v, --verbose: print what's found\n");
}


int main(int argc, char **argv) {
        int rc, i, verbose = 0;
        struct p9_handle *p9_handle;
	struct file_handle *fhandle;
	char buf[1024];

	char *conffile = DEFAULT_CONFFILE;
	char *server = DEFAULT_SERVER;
	char *port = NULL;

        static struct option long_options[] = {
                { "conf",       required_argument,      0,              'c' },
                { "server",     required_argument,      0,              's' },
                { "port",       required_argument,      0,              'p' },
                { "help",       no_argument,            0,              'h' },
                { "verbose",    no_argument,            0,              'v' },
                { 0,            0,                      0,               0  }
        };

        int option_index = 0;
        int op;

        while ((op = getopt_long(argc, argv, "@vc:s:ht:", long_options, &option_index)) != -1) {
                switch(op) {
                        case '@':
                                printf("%s compiled on %s at %s\n", argv[0], __DATE__, __TIME__);
                                printf("Release = %s\n", VERSION);
                                printf("Release comment = %s\n", VERSION_COMMENT);
                                printf("Git HEAD = %s\n", _GIT_HEAD_COMMIT ) ;
                                printf("Git Describe = %s\n", _GIT_DESCRIBE ) ;
                                exit(0);
                        case 'h':
                                print_help(argv);
                                exit(0);
                        case 'c':
                                conffile = optarg;
                                break;
                        case 's':
                                server = optarg;
                                break;
                        case 'p':
                                port = optarg;
                                break;
                        case 'v':
                                verbose = 1;
                                break;
                        default:
                                ERROR_LOG("Failed to parse arguments");
                                print_help(argv);
                                exit(EINVAL);
                }
        }

        if (optind < argc) {
                for (i = optind; i < argc; i++)
                        printf ("Leftover argument %s\n", argv[i]);
                print_help(argv);
                exit(EINVAL);
        }

        rc = liop_init(&p9_handle, conffile, server, port);
        if (rc) {
                ERROR_LOG("Init failure: %s (%d)", strerror(rc), rc);
                return rc;
        }

        INFO_LOG(1, "Init success");

	rc = liop_status(p9_handle, "foo");
	INFO_LOG(verbose, "status rc: %d", rc);

	rc = liop_gethandle(p9_handle, "/", "/tmp/foo", 0, &fhandle);
	INFO_LOG(verbose, "gethandle rc: %d", rc);

	rc = liop_write(p9_handle, "/", fhandle, 0, "space9 writes!", 14, 0);
	INFO_LOG(verbose, "write rc: %d", rc);

	rc = liop_read(p9_handle, "/", fhandle, 0, buf, 100, 0);
	INFO_LOG(verbose, "read rc: %d, text: %.*s", rc, rc, buf);

	uint64_t reqid;
	uint32_t count;
	msk_rloc_t *rloc;
	rc = liop_write_rdma_init(p9_handle, "/", fhandle, 0, 0, 100*1024*1024, &reqid, &count, &rloc);
	INFO_LOG(verbose, "write rdma init rc: %d", rc);

	msk_data_t data;
	data.data = malloc(1024*1024*100);
	memset(data.data, 42, 1024*1024*100);
	data.size = 1024*1024*100;
	data.max_size = 1024*1024*100;
	data.next = NULL;
	data.mr = msk_reg_mr(p9_handle->trans, data.data, 100*1024*1024, IBV_ACCESS_LOCAL_WRITE);

	rc = msk_wait_write(p9_handle->trans, &data, rloc);
	INFO_LOG(verbose, "msk_write_wait: %d\n", rc);

	rc = liop_write_rdma_fini(p9_handle, reqid);
	INFO_LOG(verbose, "write rdma fini rc: %d", rc);
	

	free(fhandle);
        p9_destroy(&p9_handle);
                
        return rc;
}
