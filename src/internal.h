/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/18.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef UVSOCKS5_INTERNAL_H
#define UVSOCKS5_INTERNAL_H

#include <assert.h>
#include "uv.h"
#include "uvsocks5/uvsocks5.h"
#include "s5.h"

enum sess_state {
    s_handshake,        /* Wait for client handshake. */
    s_req_start,        /* Start waiting for request data. */
    s_req_parse,        /* Wait for request data. */
    s_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    s_req_connect,      /* Wait for uv_tcp_connect() to complete. */
    s_dgram_start,
    s_dgram_stop,
    s_proxy_start,      /* Connected. Start piping data. */
    s_proxy,            /* Connected. Pipe data back and forth. */
    s_kill,             /* Tear down session. */
    s_almost_dead_0,    /* Waiting for finalizers to complete. */
    s_almost_dead_1,    /* Waiting for finalizers to complete. */
    s_almost_dead_2,    /* Waiting for finalizers to complete. */
    s_almost_dead_3,    /* Waiting for finalizers to complete. */
    s_almost_dead_4,    /* Waiting for finalizers to complete. */
    s_dead,             /* Dead. Safe to free now. */

    s_max
};

enum conn_state {
    c_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    c_done,  /* Done; read incoming data or write finished. */
    c_stop,  /* Stopped. */
    c_dead
};

typedef enum {
    peer,
    sock
}endpoint;

typedef struct UVSOCKS5_BUF{
    char *buf_base;
    size_t buf_len;
}UVSOCKS5_BUF;

typedef struct {
    unsigned char rdstate;
    unsigned char wrstate;
    unsigned int idle_timeout;
    struct PROXY_NODE *pn;  /* Backlink */
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
    } handle;
    uv_timer_t timer_handle;  /* For detecting timeouts. */
    uv_write_t write_req;
    /* We only need one of these at a time so make them share memory. */
    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;

        char raw[MAX_S5_TCP_FRAME_LEN];
    } t;

    ADDRESS peer;
    UVSOCKS5_BUF us_buf;
} CONN;

typedef struct PROXY_NODE {
    int state;
    unsigned int index;
    uv_loop_t *loop;

    CONN incoming;
    CONN outgoing;
    int outstanding;

    struct DGRAM_NODE *dn;   /* dgram node */
    s5_ctx parser;

    char link_info[128];

    void *ctx;
} PROXY_NODE;

enum{
    u_using,
    u_closing0,
    u_closing1,
    u_closing2,
    u_dead
};

typedef struct DGRAM_LOCAL{
    struct DGRAM_NODE *dn;
    union {
        uv_handle_t handle;
        uv_udp_t udp;
    } handle;

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr;

    ADDRESS peer;

    uv_udp_send_t req_send;

    char slab[MAX_S5_UDP_FRAME_LEN];
    UVSOCKS5_BUF us_buf;
}DGRAM_LOCAL;

typedef struct DGRAM_REMOTE{
    int state;

    /* TODO: DGRAM ONE TO MORE */
//    struct DGRAMS *next;
    struct DGRAM_NODE *dn;

    char link_info[128];

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr;

    union {
        uv_handle_t handle;
        uv_udp_t udp;
    } handle;

    ADDRESS peer;

    uv_udp_send_t req_send;
    uv_getaddrinfo_t req_dns;

    char slab[MAX_S5_UDP_FRAME_LEN]; /* for recv */
    UVSOCKS5_BUF us_buf;

    void *ctx;
} DGRAM_REMOTE;

typedef struct DGRAM_NODE{
    int state;
    DGRAM_LOCAL incoming;
    DGRAM_REMOTE outgoing;

    PROXY_NODE *pn;

    uv_timer_t timer;
}DGRAM_NODE;



#define BREAK_LABEL                                     \
    cleanup

#define BREAK_ON_FAILURE_WITH_LABEL(_status, label)     \
if ( (_status) != 0 )                                   \
    goto label

#define BREAK_ON_FAILURE(_status)                       \
    BREAK_ON_FAILURE_WITH_LABEL(_status, BREAK_LABEL)

#define BREAK_ON_NULL_WITH_LABEL(value, label)          \
if ( !(value) )                                         \
    goto label

#define BREAK_ON_NULL(_value)                           \
    BREAK_ON_NULL_WITH_LABEL(_value, BREAK_LABEL)

#define BREAK_ON_FALSE        BREAK_ON_NULL

#define BREAK_NOW                                       \
    goto BREAK_LABEL

#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)     do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif

#define ENSURE(exp)     do { if (!(exp)) abort(); } while (0)

#define UNREACHABLE()   CHECK(!"Unreachable code reached.")


#define htons_u(x)          (unsigned short)( (((x) & 0xffu) << 8u) | (((x) & 0xff00u) >> 8u) )
#define ntohs_u(x)          htons_u(x)

#define ntohl_u(x)        ( (((x) & 0xffu) << 24u) | \
                            (((x) & 0xff00u) << 8u) | \
                            (((x) & 0xff0000u) >> 8u) | \
                            (((x) & 0xff000000) >> 24u) )
#define htonl_u(x)          ntohl_u(x)


#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

enum {
    s5_invalid_length = -1,
    s5_invalid_version = -2,
    s5_invalid_method = -3
};

/* URIL.C */
int str_sockaddr(const struct sockaddr *addr, ADDRESS *addr_s);
void cpy_sockaddr(const struct sockaddr *src, struct sockaddr *dst);
int equal_sockaddr(const struct sockaddr *src, struct sockaddr *dst);
void set_sockaddr_port(struct sockaddr *addr, unsigned short port);
int str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, ADDRESS *addr_s);
int str_udp_endpoint(const uv_udp_t *udp_handle, ADDRESS *addr_s);
int s5_simple_check(const char *data, size_t data_len);
int s5_addr_copy(s5_ctx *ctx, struct sockaddr *addr, ADDRESS *addr_s);

/* BASE.C */
void uvsocks5_on_msg(int level, const char *format, ...);
void uvsocks5_on_bind(const char *host, unsigned short port);
void uvsocks5_on_connection_made(PROXY_NODE *pn);
void uvsocks5_on_new_stream(CONN *conn);
void uvsocks5_on_stream_teardown(PROXY_NODE *pn);
void uvsocks5_on_new_dgram(ADDRESS *local, ADDRESS *remote, void **ctx);
void uvsocks5_on_dgram_teardown(void *ctx);
int uvsocks5_on_plain_stream(CONN *conn);
void uvsocks5_on_plain_dgram(UVSOCKS5_BUF *buf, int direct, void *ctx);
int uvsocks5_write_stream_out(
    MEM_RANGE *buf, int direct, void *stream_id,
    write_stream_out_callback callback, void *param);
void uvsocks5_shutdown_link(void *stream_id);

/* SERVER.C */
void conn_write(CONN *conn, const void *data, unsigned int len);
void conn_read(CONN *conn);
void conn_timer_reset(CONN *conn);
int conn_connect(CONN *conn);
int conn_cycle(const char *who, CONN *a, CONN *b);
void conn_connect_done(uv_connect_t *req, int status);
void conn_getaddrinfo(CONN *conn, const char *hostname);
void conn_close(CONN *conn);

/* FLOW.C */
int do_kill(PROXY_NODE *pn);
void do_next(CONN *sender);

extern UVSOCKS5_CTX uvsocks5_ctx;
extern unsigned int pn_outstanding;

#endif //UVSOCKS5_INTERNAL_H
