/*
 * Copyright CEA/DAM/DIF (2016)
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

#ifndef LIOP_PROTO_INTERNALS
#define LIOP_PROTO_INTERNALS


/* Replies should have that bit set */
#define LIOP_REPLY 0x80

enum liop_request_type {
        LIOP_TCAPABILITY = 0,
        LIOP_RCAPABILITY = LIOP_TCAPABILITY | LIOP_REPLY,
        LIOP_TAUTH = 1,
        LIOP_RAUTH = LIOP_TAUTH | LIOP_REPLY,
        LIOP_TSTATUS = 2,
        LIOP_RSTATUS = LIOP_TSTATUS | LIOP_REPLY,
        LIOP_TWRITE = 3,
        LIOP_RWRITE = LIOP_TWRITE | LIOP_REPLY,
        LIOP_TREAD = 4,
        LIOP_RREAD = LIOP_TREAD | LIOP_REPLY,
        LIOP_TGETHANDLE = 5,
        LIOP_RGETHANDLE = LIOP_TGETHANDLE | LIOP_REPLY,
        LIOP_TERROR = 9, /* TERROR does not make sense */
        LIOP_RERROR = LIOP_TERROR | LIOP_REPLY,
        LIOP_TWRITE_RDMA = 10,
        LIOP_RWRITE_RDMA = LIOP_TWRITE_RDMA | LIOP_REPLY,
        LIOP_TWRITE_RDMA_INIT = 11,
        LIOP_RWRITE_RDMA_INIT = LIOP_TWRITE_RDMA_INIT | LIOP_REPLY,
        LIOP_TWRITE_RDMA_FINI = 12,
        LIOP_RWRITE_RDMA_FINI = LIOP_TWRITE_RDMA_FINI | LIOP_REPLY,
        LIOP_TREAD_RDMA = 20,
        LIOP_RREAD_RDMA = LIOP_TREAD_RDMA | LIOP_REPLY,
        LIOP_TREAD_RDMA_INIT = 21,
        LIOP_RREAD_RDMA_INIT = LIOP_TREAD_RDMA_INIT | LIOP_REPLY,
        LIOP_TREAD_RDMA_FINI = 22,
        LIOP_RREAD_RDMA_FINI = LIOP_TREAD_RDMA_FINI | LIOP_REPLY,
};


#define liop_getheader( __cursor, __var) \
do { \
  __cursor += P9_HDR_SIZE; \
  __var = *(uint16_t*)__cursor; \
  __cursor += 4; \
} while( 0 )

#define liop_initcursor( __cursor, __start, __msgtype, __tag ) \
do {                                                         \
  __cursor = __start + P9_HDR_SIZE;                          \
  *((uint16_t *)__cursor) = __msgtype;                       \
  __cursor += sizeof( uint16_t );                            \
  *((uint16_t *)__cursor) = __tag;                           \
  __cursor += sizeof( uint16_t );                            \
} while( 0 )

#define liop_padding( __cursor, __start )    \
do {                                         \
  int __padnum = (__cursor - __start) % 16;  \
  /* cannot trick like __cursor + 15 & 0xf because we need to  \
   * align vs. __start; if you have better... \
   * check start alignment then do it? */     \
  if (__padnum)                               \
    __padnum = 16 - __padnum;                 \
  while (__padnum-- > 0)                      \
    *(cursor++) = 0;                          \
} while( 0 )

#endif
