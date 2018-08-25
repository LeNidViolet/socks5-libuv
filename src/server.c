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

#include <stdlib.h>
#include "uvsocks5/uvsocks5.h"
#include "internal.h"
#include "dnsc.h"

UVSOCKS5_CTX uvsocks5_ctx;
unsigned int pn_outstanding = 0;

static int server_run(UVSOCKS5_CTX *ctx);
static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void on_connection(uv_stream_t *server, int status);
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void conn_write_done(uv_write_t *req, int status);
static void conn_close_done(uv_handle_t *handle);
static void conn_timer_expire(uv_timer_t *handle);
static void conn_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *ai);

static void loop_walk_clear(uv_loop_t *loop);
static void loop_walk_cb(uv_handle_t* handle, void* arg);
static void loop_walk_close_done(uv_handle_t* handle);

void uvsocks5_server_port(UVSOCKS5_PORT *port) {
    port->write_stream_out = uvsocks5_write_stream_out;
    port->shutdown_link = uvsocks5_shutdown_link;
}

int uvsocks5_server_launch(UVSOCKS5_CTX *ctx) {
    int ret = -1;

    BREAK_ON_NULL(ctx);

    dnsc_init();

    memcpy(&uvsocks5_ctx, ctx, sizeof(uvsocks5_ctx));
    if ( !uvsocks5_ctx.config.bind_host )
        uvsocks5_ctx.config.bind_host = DEFAULT_S5_BIND_HOST;
    if ( !uvsocks5_ctx.config.bind_port )
        uvsocks5_ctx.config.bind_port = DEFAULT_S5_BIND_PORT;
    if ( !uvsocks5_ctx.config.idel_timeout )
        uvsocks5_ctx.config.idel_timeout = DEFAULT_S5_IDEL_TIMEOUT;

    ret = server_run(&uvsocks5_ctx);

    dnsc_clear();

BREAK_LABEL:

    return ret;
}

static int server_run(UVSOCKS5_CTX *ctx) {
    struct addrinfo hints;
    uv_loop_t *loop;
    int ret;
    uv_getaddrinfo_t req;

    loop = uv_default_loop();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    uv_req_set_data((uv_req_t *)&req, loop);
    ret = uv_getaddrinfo(loop,
                         &req,
                         do_bind,
                         ctx->config.bind_host,
                         NULL,
                         &hints);
    if ( 0 != ret ) {
        uvsocks5_on_msg(1, "uv_getaddrinfo failed: %s", uv_strerror(ret));
        BREAK_NOW;
    }

    /* Start the event loop.  Control continues in do_bind(). */
    ret = uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_close(loop);

BREAK_LABEL:

    return ret;
}


static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    char addrbuf[INET6_ADDRSTRLEN + 1];
    unsigned int naddrs;
    unsigned short port;
    struct addrinfo *ai;
    const void *addrv = NULL;
    uv_loop_t *loop;
    int ret = -1;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } s;
    uv_tcp_t *tcp_handle;

    loop = uv_req_get_data((uv_req_t *)req);

    if ( status < 0 ) {
        uvsocks5_on_msg(1, "uv_getaddrinfo failed: %s", uv_strerror(status));
        BREAK_NOW;
    }

    naddrs = 0;
    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( ai->ai_family == AF_INET || ai->ai_family == AF_INET6 ) {
            naddrs++;
        }
    }
    BREAK_ON_NULL(naddrs);

    port = uvsocks5_ctx.config.bind_port;
    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( ai->ai_family != AF_INET && ai->ai_family != AF_INET6 ) {
            continue;
        }

        if ( ai->ai_family == AF_INET ) {
            s.addr4 = *(const struct sockaddr_in *)ai->ai_addr;
            s.addr4.sin_port = htons_u(port);
            addrv = &s.addr4.sin_addr;
        }
        else if ( ai->ai_family == AF_INET6 ) {
            s.addr6 = *(const struct sockaddr_in6 *)ai->ai_addr;
            s.addr6.sin6_port = htons_u(port);
            addrv = &s.addr6.sin6_addr;
        }
        else {
            UNREACHABLE();
        }

        CHECK(0 == uv_inet_ntop(
            s.addr.sa_family,
            addrv,
            addrbuf,
            sizeof(addrbuf)));

        /* tcp bind */
        ENSURE((tcp_handle = malloc(sizeof(*tcp_handle))) != NULL);
        CHECK(0 == uv_tcp_init(loop, tcp_handle));

        ret = uv_tcp_bind(tcp_handle, &s.addr, 0);
        if ( 0 != ret ) {
            uvsocks5_on_msg(
                1,
                "Tcp bind to %s:%d failed: %s",
                addrbuf,
                port,
                uv_strerror(ret));
            BREAK_NOW;
        }

        ret = uv_listen((uv_stream_t *)tcp_handle, SOMAXCONN, on_connection);
        if ( 0 != ret ) {
            uvsocks5_on_msg(
                1,
                "Tcp listen to %s:%d failed: %s",
                addrbuf,
                port,
                uv_strerror(ret));
            BREAK_NOW;
        }

        uvsocks5_on_bind(addrbuf, port);
    }

BREAK_LABEL:

    if ( addrs )
        uv_freeaddrinfo(addrs);

    if ( 0 != ret )
        loop_walk_clear(loop);
}

static void on_connection(uv_stream_t *server, int status) {
    static unsigned int index = 0;
    uv_loop_t *loop;
    PROXY_NODE *pn;
    CONN *incoming;
    CONN *outgoing;

    BREAK_ON_FALSE(0 == status);

    loop = uv_handle_get_loop((uv_handle_t *)server);

    ENSURE((pn = malloc(sizeof(*pn))) != NULL);
    memset(pn, 0, sizeof(*pn));

    pn->state = s_handshake;
    pn->outstanding = 0;
    pn->index = index++;
    pn->loop = loop;
    pn->ctx = NULL;
    s5_init(&pn->parser);

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    CHECK(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    CHECK(0 == uv_accept(server, &incoming->handle.stream));
    uv_handle_set_data(&incoming->handle.handle, incoming);
    incoming->pn = pn;
    incoming->result = 0;
    incoming->rdstate = c_stop;
    incoming->wrstate = c_stop;
    incoming->idle_timeout = uvsocks5_ctx.config.idel_timeout;
    CHECK(0 == uv_timer_init(loop, &incoming->timer_handle));

    CHECK(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    uv_handle_set_data(&outgoing->handle.handle, outgoing);
    outgoing->pn = pn;
    outgoing->result = 0;
    outgoing->rdstate = c_stop;
    outgoing->wrstate = c_stop;
    outgoing->idle_timeout = uvsocks5_ctx.config.idel_timeout;
    CHECK(0 == uv_timer_init(loop, &outgoing->timer_handle));

    /* Emit a notify */
    uvsocks5_on_new_stream(incoming);
    incoming->us_buf.buf_base = incoming->t.raw;
    incoming->us_buf.buf_len = sizeof(incoming->t.raw);
    outgoing->us_buf.buf_base = outgoing->t.raw;
    outgoing->us_buf.buf_len = sizeof(outgoing->t.raw);

    pn_outstanding++;

    /* Wait for the initial packet. */
    conn_read(incoming);

BREAK_LABEL:

    return;
}

int conn_connect(CONN *conn) {
    int ret;

    ASSERT(conn->t.addr.sa_family == AF_INET ||
           conn->t.addr.sa_family == AF_INET6);

    ret = uv_tcp_connect(&conn->t.connect_req,
                         &conn->handle.tcp,
                         &conn->t.addr,
                         conn_connect_done);
    if ( 0 == ret ) {
        conn->pn->outstanding++;
        conn_timer_reset(conn);
    }

    return ret;
}

void conn_connect_done(uv_connect_t *req, int status) {
    CONN *conn;

    conn = CONTAINER_OF(req, CONN, t.connect_req);
    conn->result = status;

    conn->pn->outstanding--;
    do_next(conn);
}

static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    CONN *conn;

    (void)size;

    conn = uv_handle_get_data(handle);

    buf->base = conn->us_buf.buf_base;
    buf->len = conn->us_buf.buf_len;
}

void conn_read(CONN *conn) {
    ASSERT(conn->rdstate == c_stop);

    if( 0 != uv_read_start(
        &conn->handle.stream,
        conn_alloc,
        conn_read_done) ) {

        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->rdstate = c_busy;
    conn_timer_reset(conn);

BREAK_LABEL:

    return;
}

static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    CONN *conn;

    conn = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(conn->us_buf.buf_base == buf->base);
    ASSERT(conn->rdstate == c_busy);
    conn->rdstate = c_done;
    conn->result = nread;

    uv_read_stop(&conn->handle.stream);
    do_next(conn);
}

void conn_write(CONN *conn, const void *data, unsigned int len) {
    uv_buf_t buf;

    ASSERT(conn->wrstate == c_stop || conn->wrstate == c_done);
    conn->wrstate = c_busy;

    buf = uv_buf_init((char*)data, len);

    if ( 0 != uv_write(&conn->write_req,
                       &conn->handle.stream,
                       &buf,
                       1,
                       conn_write_done) ) {
        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->pn->outstanding++;
    conn_timer_reset(conn);

BREAK_LABEL:

    return;
}

static void conn_write_done(uv_write_t *req, int status) {
    CONN *conn;

    conn = CONTAINER_OF(req, CONN, write_req);
    conn->pn->outstanding--;
    ASSERT(conn->wrstate == c_busy);
    conn->wrstate = c_done;
    conn->result = status;

    do_next(conn);
}

void conn_getaddrinfo(CONN *conn, const char *hostname) {
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    CHECK(0 == uv_getaddrinfo(conn->pn->loop,
                              &conn->t.addrinfo_req,
                              conn_getaddrinfo_done,
                              hostname,
                              NULL,
                              &hints));
    conn->pn->outstanding++;
    conn_timer_reset(conn);
}

static void conn_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *ai) {
    CONN *conn;

    conn = CONTAINER_OF(req, CONN, t.addrinfo_req);
    conn->result = status;

    if (status == 0) {
        /* FIXME(bnoordhuis) Should try all addresses. */
        if (ai->ai_family == AF_INET) {
            conn->t.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        } else if (ai->ai_family == AF_INET6) {
            conn->t.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        } else {
            UNREACHABLE();
        }
        set_sockaddr_port(&conn->t.addr, htons_u(conn->peer.port));
    }

    uv_freeaddrinfo(ai);

    conn->pn->outstanding--;
    do_next(conn);
}

void conn_close(CONN *conn) {
    ASSERT(conn->rdstate != c_dead);
    ASSERT(conn->wrstate != c_dead);
    conn->rdstate = c_dead;
    conn->wrstate = c_dead;
    uv_handle_set_data((uv_handle_t*)&conn->timer_handle, conn);
    uv_handle_set_data(&conn->handle.handle, conn);
    uv_close(&conn->handle.handle, conn_close_done);
    uv_close((uv_handle_t *) &conn->timer_handle, conn_close_done);
}

static void conn_close_done(uv_handle_t *handle) {
    CONN *conn;

    conn = uv_handle_get_data(handle);
    do_next(conn);
}


void conn_timer_reset(CONN *conn) {
    CHECK(0 == uv_timer_start(&conn->timer_handle,
                              conn_timer_expire,
                              conn->idle_timeout,
                              0));
}

int conn_cycle(const char *who, CONN *a, CONN *b) {
    if ( a->result < 0 ) {
        if ( a->result != UV_EOF ) {
            uvsocks5_on_msg(
                1,
                "[%d] %s error: %s [%s]",
                a->pn->index,
                who,
                uv_strerror((int)a->result),
                a->pn->link_info);
        }

        return -1;
    }

    if ( b->result < 0 ) {
        return -1;
    }

    if ( a->wrstate == c_done ) {
        a->wrstate = c_stop;
    }

    /* The logic is as follows: read when we don't write and write when we don't
     * read.  That gives us back-pressure handling for free because if the peer
     * sends data faster than we consume it, TCP congestion control kicks in.
     */
    if ( a->wrstate == c_stop ) {
        if ( b->rdstate == c_stop ) {
            conn_read(b);
        }
        else if ( b->rdstate == c_done ) {
            conn_write(a, b->us_buf.buf_base, (unsigned int)b->result);
            b->rdstate = c_stop;  /* Triggers the call to conn_read() above. */
        }
    }

    return 0;
}

static void conn_timer_expire(uv_timer_t *handle) {
    CONN *conn;
    CONN *incoming;
    CONN *outgoing;

    conn = CONTAINER_OF(handle, CONN, timer_handle);

    incoming = &conn->pn->incoming;
    outgoing = &conn->pn->outgoing;

    switch ( conn->pn->state ) {
    case s_handshake:
    case s_req_start:
    case s_req_parse:
    case s_dgram_start:
    case s_dgram_stop:
        ASSERT(conn == incoming);
        incoming->result = UV_ETIMEDOUT;
        break;
    case s_req_lookup:
    case s_req_connect:
    case s_proxy_start:
        outgoing->result = UV_ETIMEDOUT;
        break;
    default:
        conn->result = UV_ETIMEDOUT;  /* s_proxy, .. */
        break;
    }
    do_next(conn);
}

static void loop_walk_clear(uv_loop_t *loop) {
    uv_walk(loop, loop_walk_cb, NULL);
}

static void loop_walk_cb(uv_handle_t* handle, void* arg) {
    uv_handle_type type;
    UVSOCKS5_BUF *us_buf;

    (void)arg;

    type = uv_handle_get_type(handle);
    if ( UV_TCP == type ) {

        uv_close(handle, loop_walk_close_done);
    } else if ( UV_UDP == type ) {
        us_buf = uv_handle_get_data(handle);

        ASSERT(us_buf);
        ASSERT(us_buf->buf_base);
        free(us_buf->buf_base);
        free(us_buf);

        uv_close(handle, loop_walk_close_done);
    } else {
        uv_close(handle, NULL);
    }
}

static void loop_walk_close_done(uv_handle_t* handle) {
    free(handle);
}
