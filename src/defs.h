/* Copyright StrongLoop, Inc. All rights reserved.
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

#ifndef DEFS_H_
#define DEFS_H_

#include "s5.h"
#include "uv.h"

#include <assert.h>
#include <netinet/in.h>  /* sockaddr_in, sockaddr_in6 */
#include <stddef.h>      /* size_t, ssize_t */
#include <stdint.h>
#include <sys/socket.h>  /* sockaddr */

struct client_ctx;

typedef struct {
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idle_timeout;

    const char *username;
    const char *password;
    int auth_none;
} server_config;

typedef struct {
    unsigned int idle_timeout;  /* Connection idle timeout in ms. */
    unsigned short bind_port;
    uv_tcp_t tcp_handle;
    uv_udp_t udp_handle;
    uv_loop_t *loop;

    const char *username;
    const char *password;
    int auth_none;

    struct client_endpoint *cp_link;    /* Link head */
} server_ctx;

typedef struct {
    unsigned char rdstate;
    unsigned char wrstate;
    unsigned int idle_timeout;
    struct client_ctx *client;  /* Backlink to owning client context. */
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
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
        char buf[2048];  /* Scratch space. Used to read data into. */
    } t;
} conn;

/* Maximum Payload length *in general* */
#define MAX_UDP_PAYLOAD_LEN             512
#define S5_IPV4_UDP_SEND_HDR_LEN        10
#define S5_IPV6_UDP_SEND_HDR_LEN        22

/* Just in ip fmt */
#define MAX_S5_UDP_SEND_HDR_LEN         S5_IPV6_UDP_SEND_HDR_LEN

/* server link (udp client can send data to multiple different addresses) */
typedef struct server_endpoint {
    struct server_endpoint *next;

    /* destination address */
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } server;

    char buf[MAX_UDP_PAYLOAD_LEN + MAX_S5_UDP_SEND_HDR_LEN];  /* max udp packet len + max s5 hdr len */

    uv_udp_send_t send_req;
    uv_udp_t handle;

    char link_info[128];

    struct client_endpoint *cp;  /* Backlink */
} server_endpoint;

/* for each incoming proxy request, indicate by ip:port */
typedef struct client_endpoint {
    struct client_endpoint *next;

    /* udp client address */
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } client;

    struct server_endpoint *sp; /* server endpoint list head */

    struct client_ctx *cx;  /* Backlink */
} client_endpoint;


typedef struct server_endpoint_param {
    client_endpoint *cp;

    const char *data;
    size_t data_len;

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;

    union {
        uv_udp_send_t send_req;
        uv_getaddrinfo_t getaddr_req;
    } r;
} server_endpoint_param;


typedef struct client_ctx {
    int state;
    int index;
    server_ctx *sx;  /* Backlink to owning server context. */
    s5_ctx parser;  /* The SOCKS protocol parser. */
    conn incoming;  /* Connection with the SOCKS client. */
    conn outgoing;  /* Connection with upstream. */
    client_endpoint *cp;
    int outstanding;

    char link_info[128];
} client_ctx;

/* server.c */
int server_run(const server_config *cf, uv_loop_t *loop);
int can_auth_none(const server_ctx *sx, const client_ctx *cx);
int can_auth_passwd(const server_ctx *sx, const client_ctx *cx);
int can_access(const server_ctx *sx,
    const client_ctx *cx,
    const struct sockaddr *addr);

/* client.c */
void client_finish_init(server_ctx *sx, client_ctx *cx);
void client_endpoint_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void client_endpoint_read_done(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags
);


/* util.c */
#if defined(__GNUC__)
# define ATTRIBUTE_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
# define ATTRIBUTE_FORMAT_PRINTF(a, b)
#endif
void pr_info(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_warn(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_err(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void *xmalloc(size_t size);

typedef enum {
    peer,
    sock
}endpoint;
int str_sockaddr(const struct sockaddr *addr, char *buf, int buf_len);
int str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, char *buf, int buf_len);
int str_udp_endpoint(const uv_udp_t *udp_handle, char *buf, int buf_len);
void desc_tcp_proxy_link(client_ctx *cx);
void desc_udp_endpoint_link(client_ctx *cx, server_endpoint *sp);
void desc_upd_proxy_link(client_ctx *cx);

/* main.c */
const char *_getprogname(void);

/* getopt.c */
#if !HAVE_UNISTD_H
extern char *optarg;
int getopt(int argc, char **argv, const char *options);
#endif

/* ASSERT() is for debug checks, CHECK() for run-time sanity checks.
 * DEBUG_CHECKS is for expensive debug checks that we only want to
 * enable in debug builds but still want type-checked by the compiler
 * in release builds.
 */
#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)   do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif

#define ENSURE(exp)      do { if (!(exp)) abort(); } while (0)

#define UNREACHABLE() CHECK(!"Unreachable code reached.")

#define htons_u(x)          (unsigned short)( (((x) & 0xffu) << 8u) | (((x) & 0xff00u) >> 8u) )
#define ntohs_u(x)          htons_u(x)

#define ntohl_u(x)        ( (((x) & 0xffu) << 24u) | \
                            (((x) & 0xff00u) << 8u) | \
                            (((x) & 0xff0000u) >> 8u) | \
                            (((x) & 0xff000000) >> 24u) )
#define htonl_u(x)          ntohl_u(x)

/* This macro looks complicated but it's not: it calculates the address
 * of the embedding struct through the address of the embedded struct.
 * In other words, if struct A embeds struct B, then we can obtain
 * the address of A by taking the address of B and subtracting the
 * field offset of B in A.
 */
#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#endif  /* DEFS_H_ */
