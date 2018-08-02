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

#include "defs.h"
#include <stdlib.h>

/* A connection is modeled as an abstraction on top of two simple state
 * machines, one for reading and one for writing.  Either state machine
 * is, when active, in one of three states: busy, done or stop; the fourth
 * and final state, dead, is an end state and only relevant when shutting
 * down the connection.  A short overview:
 *
 *                          busy                  done           stop
 *  ----------|---------------------------|--------------------|------|
 *  readable  | waiting for incoming data | have incoming data | idle |
 *  writable  | busy writing out data     | completed write    | idle |
 *
 * We could remove the done state from the writable state machine. For our
 * purposes, it's functionally equivalent to the stop state.
 *
 * When the connection with upstream has been established, the client_ctx
 * moves into a state where incoming data from the client is sent upstream
 * and vice versa, incoming data from upstream is sent to the client.  In
 * other words, we're just piping data back and forth.  See conn_cycle()
 * for details.
 *
 * An interesting deviation from libuv's I/O model is that reads are discrete
 * rather than continuous events.  In layman's terms, when a read operation
 * completes, the connection stops reading until further notice.
 *
 * The rationale for this approach is that we have to wait until the data
 * has been sent out again before we can reuse the read buffer.
 *
 * It also pleasingly unifies with the request model that libuv uses for
 * writes and everything else; libuv may switch to a request model for
 * reads in the future.
 */
enum conn_state {
    c_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    c_done,  /* Done; read incoming data or write finished. */
    c_stop,  /* Stopped. */
    c_dead
};

/* Session states. */
enum sess_state {
    s_handshake,        /* Wait for client handshake. */
    s_auth_start,       /* Start auth username password */
    s_handshake_auth,   /* Wait for client authentication data. */
    s_req_start,        /* Start waiting for request data. */
    s_req_parse,        /* Wait for request data. */
    s_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    s_req_connect,      /* Wait for uv_tcp_connect() to complete. */
    s_udp_proxy_start,
    s_udp_proxy_until,
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

static void do_next(client_ctx *cx);
static int do_handshake(client_ctx *cx);
static int do_auth_start(client_ctx *cx);
static int do_handshake_auth(client_ctx *cx);
static int do_req_start(client_ctx *cx);
static int do_req_parse(client_ctx *cx);
static int do_req_lookup(client_ctx *cx);
static int do_req_connect_start(client_ctx *cx);
static int do_req_connect(client_ctx *cx);
static int do_proxy_start(client_ctx *cx);
static int do_proxy(client_ctx *cx);
static int do_udp_response(client_ctx *cx);
static int do_udp_proxy_start(client_ctx *cx);
static int do_udp_proxy_stop(client_ctx *cx);
static int do_kill(client_ctx *cx);
static int do_clear(client_ctx *cx);
static int do_almost_dead(client_ctx *cx);
static int conn_cycle(const char *who, conn *a, conn *b);
static void conn_timer_reset(conn *c);
static void conn_timer_expire(uv_timer_t *handle);
static void conn_getaddrinfo(conn *c, const char *hostname);
static void conn_getaddrinfo_done(uv_getaddrinfo_t *req,
    int status,
    struct addrinfo *ai);
static int conn_connect(conn *c);
static void conn_connect_done(uv_connect_t *req, int status);
static void conn_read(conn *c);
static void conn_read_done(uv_stream_t *handle,
    ssize_t nread,
    const uv_buf_t *buf);
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void conn_write(conn *c, const void *data, unsigned int len);
static void conn_write_done(uv_write_t *req, int status);
static void conn_close(conn *c);
static void conn_close_done(uv_handle_t *handle);

static client_endpoint *client_endpoint_add(client_ctx *cx, struct sockaddr *addr);
static client_endpoint *client_endpoint_find(server_ctx *sx, struct sockaddr *addr);
static void client_endpoint_del(server_ctx *sx, client_endpoint *cp);
static void client_endpoint_send_done(uv_udp_send_t *req, int status);
static void client_endpoint_getaddr_done(
    uv_getaddrinfo_t *req,
    int status, struct addrinfo *ai
);

static server_endpoint *server_endpoint_add(client_endpoint *cp, struct sockaddr *addr);
static server_endpoint *server_endpoint_find(client_endpoint *cp, struct sockaddr *addr);
static void server_endpoint_read_done(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags
);
static void server_endpoint_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void server_endpoint_send_done(uv_udp_send_t *req, int status);
static void server_endpoint_close_done(uv_handle_t *handle);

static void send_to_server_endpoint(server_endpoint_param *param);

static int client_outstanding = 0;

/* |incoming| has been initialized by server.c when this is called. */
void client_finish_init(server_ctx *sx, client_ctx *cx) {
    static int index = 0;
    conn *incoming;
    conn *outgoing;

    cx->sx = sx;
    cx->state = s_handshake;
    cx->index = index;
    cx->cp = NULL;
    cx->outstanding = 0;
    memset(cx->link_info, 0, sizeof(cx->link_info));
    s5_init(&cx->parser);

    index = index < 0 ? 0 : index + 1;
    client_outstanding++;

    incoming = &cx->incoming;
    incoming->client = cx;
    incoming->result = 0;
    incoming->rdstate = c_stop;
    incoming->wrstate = c_stop;
    incoming->idle_timeout = sx->idle_timeout;
    CHECK(0 == uv_timer_init(sx->loop, &incoming->timer_handle));

    outgoing = &cx->outgoing;
    outgoing->client = cx;
    outgoing->result = 0;
    outgoing->rdstate = c_stop;
    outgoing->wrstate = c_stop;
    outgoing->idle_timeout = sx->idle_timeout;
    CHECK(0 == uv_tcp_init(cx->sx->loop, &outgoing->handle.tcp));
    CHECK(0 == uv_timer_init(cx->sx->loop, &outgoing->timer_handle));

    /* Wait for the initial packet. */
    conn_read(incoming);
}

/* This is the core state machine that drives the client <-> upstream proxy.
 * We move through the initial handshake and authentication steps first and
 * end up (if all goes well) in the proxy state where we're just proxying
 * data between the client and upstream.
 */
static void do_next(client_ctx *cx) {
    int new_state = s_max;

    ASSERT(cx->state != s_dead);
    switch (cx->state) {
    case s_handshake:
        new_state = do_handshake(cx);
        break;
    case s_auth_start:
        new_state = do_auth_start(cx);
        break;
    case s_handshake_auth:
        new_state = do_handshake_auth(cx);
        break;
    case s_req_start:
        new_state = do_req_start(cx);
        break;
    case s_req_parse:
        new_state = do_req_parse(cx);
        break;
    case s_req_lookup:
        new_state = do_req_lookup(cx);
        break;
    case s_req_connect:
        new_state = do_req_connect(cx);
        break;
    case s_udp_proxy_start:
        new_state = do_udp_proxy_start(cx);
        break;
    case s_udp_proxy_until:
        new_state = do_udp_proxy_stop(cx);
        break;
    case s_proxy_start:
        new_state = do_proxy_start(cx);
        break;
    case s_proxy:
        new_state = do_proxy(cx);
        break;
    case s_kill:
        new_state = do_kill(cx);
        break;
    case s_almost_dead_0:
    case s_almost_dead_1:
    case s_almost_dead_2:
    case s_almost_dead_3:
    case s_almost_dead_4:
        new_state = do_almost_dead(cx);
        break;
    default:
        UNREACHABLE();
    }
    cx->state = new_state;

    if (cx->state == s_dead)
        do_clear(cx);
}

static int do_clear(client_ctx *cx) {

    if ( cx->cp ) {
        client_endpoint_del(cx->sx, cx->cp);
        cx->cp = NULL;
    }

    pr_info("[%d] Free [%s]", cx->index, cx->link_info);

    if ( DEBUG_CHECKS) {
        memset(cx, -1, sizeof(*cx));
    }
    free(cx);

    client_outstanding--;
    if ( 0== client_outstanding )
        pr_info("Client Outstanding Back to Zero");

    return 0;
}

static int do_handshake(client_ctx *cx) {
    unsigned int methods;
    conn *incoming;
    s5_ctx *parser;
    uint8_t *data;
    size_t size;
    int err;

    parser = &cx->parser;
    incoming = &cx->incoming;

    if (incoming->result < 0) {
        pr_err("[%d] Handshake Read Error: %s", cx->index, uv_strerror((int)incoming->result));
        return do_kill(cx);
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    data = (uint8_t *) incoming->t.buf;
    size = (size_t) incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_ok) {
        conn_read(incoming);
        return s_handshake;  /* Need more data. */
    }

    if (size != 0) {
        /* Could allow a round-trip saving shortcut here if the requested auth
         * method is S5_AUTH_NONE (provided unauthenticated traffic is allowed.)
         * Requires client support however.
         */
        pr_err("[%d] Junk in Handshake", cx->index);
        return do_kill(cx);
    }

    if (err != s5_auth_select) {
        pr_err("[%d] Handshake Error: %s", cx->index, s5_strerror((s5_err)err));
        return do_kill(cx);
    }

    methods = s5_auth_methods(parser);

    if ((methods & (unsigned int)S5_AUTH_NONE) && can_auth_none(cx->sx, cx)) {
        s5_select_auth(parser, S5_AUTH_NONE);
        conn_write(incoming, "\5\0", 2);  /* No auth required. */
        return s_req_start;
    }

    if ((methods & (unsigned int)S5_AUTH_PASSWD) && can_auth_passwd(cx->sx, cx)) {
        s5_select_auth(parser, S5_AUTH_PASSWD);
        conn_write(incoming, "\5\2", 2);  /* Require username password */
        return s_auth_start;
    }

    conn_write(incoming, "\5\255", 2);  /* No acceptable auth. */
    return s_kill;
}

static int do_auth_start(client_ctx *cx) {
    conn *incoming;

    incoming = &cx->incoming;

    if (incoming->result < 0) {
        pr_err("[%d] Auth Write Error: %s", cx->index, uv_strerror((int)incoming->result));
        return do_kill(cx);
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    incoming->wrstate = c_stop;

    conn_read(incoming);
    return s_handshake_auth;
}

static int do_handshake_auth(client_ctx *cx) {
    conn *incoming;
    s5_ctx *parser;
    uint8_t *data;
    size_t size;
    int err;

    parser = &cx->parser;
    incoming = &cx->incoming;

    if (incoming->result < 0) {
        pr_err("[%d] Handshake Auth Read Error: %s", cx->index, uv_strerror((int)incoming->result));
        return do_kill(cx);
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    data = (uint8_t *) incoming->t.buf;
    size = (size_t) incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_ok) {
        conn_read(incoming);
        return s_handshake_auth;  /* Need more data. */
    }

    if (size != 0) {

        pr_err("[%d] Junk in Handshake auth", cx->index);
        return do_kill(cx);
    }

    if ( err != s5_auth_verify ) {
        pr_err("[%d] Handshake auth Error: %s", cx->index, s5_strerror((s5_err)err));
        return do_kill(cx);
    }

    if (
        strlen((const char*)parser->username) == strlen(cx->sx->username) &&
        strlen((const char*)parser->password) == strlen(cx->sx->password) &&
        0 == memcmp((const char*)parser->username, cx->sx->username, strlen(cx->sx->username)) &&
        0 == memcmp((const char*)parser->password, cx->sx->password, strlen(cx->sx->password))
        )
    {
        conn_write(incoming, "\1\0", 2);
        return s_req_start;
    }
    else
    {
        conn_write(incoming, "\1\1", 2);
        return s_kill;
    }
}

static int do_req_start(client_ctx *cx) {
    conn *incoming;

    incoming = &cx->incoming;

    if (incoming->result < 0) {
        pr_err("[%d] Auth Reply Write Error: %s", cx->index, uv_strerror((int)incoming->result));
        return do_kill(cx);
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    incoming->wrstate = c_stop;

    conn_read(incoming);
    return s_req_parse;
}

static int do_req_parse(client_ctx *cx) {
    conn *incoming;
    conn *outgoing;
    s5_ctx *parser;
    uint8_t *data;
    size_t size;
    int err;

    parser = &cx->parser;
    incoming = &cx->incoming;
    outgoing = &cx->outgoing;

    if (incoming->result < 0) {
        pr_err("[%d] S5 Request Read Error: %s", cx->index, uv_strerror((int)incoming->result));
        return do_kill(cx);
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);
    incoming->rdstate = c_stop;

    data = (uint8_t *) incoming->t.buf;
    size = (size_t) incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_ok) {
        conn_read(incoming);
        return s_req_parse;  /* Need more data. */
    }

    if (size != 0) {
        pr_err("[%d] Junk in Equest %u", cx->index, (unsigned) size);
        return do_kill(cx);
    }

    if (err != s5_exec_cmd) {
        pr_err("[%d] Request Error: %s", cx->index, s5_strerror((s5_err)err));
        return do_kill(cx);
    }

    if (parser->cmd == s5_cmd_tcp_bind) {
        /* Not supported but relatively straightforward to implement. */
        pr_warn("[%d] BIND requests are not supported.", cx->index);
        return do_kill(cx);
    }

    if (parser->cmd == s5_cmd_udp_assoc) {
        return do_udp_response(cx);
    }
    ASSERT(parser->cmd == s5_cmd_tcp_connect);

    if (parser->atyp == s5_atyp_host) {
        conn_getaddrinfo(outgoing, (const char *) parser->daddr);
        return s_req_lookup;
    }

    if (parser->atyp == s5_atyp_ipv4) {
        memset(&outgoing->t.addr4, 0, sizeof(outgoing->t.addr4));
        outgoing->t.addr4.sin_family = AF_INET;
        outgoing->t.addr4.sin_port = htons_u(parser->dport);
        memcpy(&outgoing->t.addr4.sin_addr,
               parser->daddr,
               sizeof(outgoing->t.addr4.sin_addr));
    } else if (parser->atyp == s5_atyp_ipv6) {
        memset(&outgoing->t.addr6, 0, sizeof(outgoing->t.addr6));
        outgoing->t.addr6.sin6_family = AF_INET6;
        outgoing->t.addr6.sin6_port = htons_u(parser->dport);
        memcpy(&outgoing->t.addr6.sin6_addr,
               parser->daddr,
               sizeof(outgoing->t.addr6.sin6_addr));
    } else {
        UNREACHABLE();
    }

    return do_req_connect_start(cx);
}

static int do_req_lookup(client_ctx *cx) {
    s5_ctx *parser;
    conn *incoming;
    conn *outgoing;

    parser = &cx->parser;
    incoming = &cx->incoming;
    outgoing = &cx->outgoing;

    if (outgoing->result < 0) {
        /* TODO(bnoordhuis) Escape control characters in parser->daddr. */
        pr_err("[%d] Lookup Error For \"%s\": %s",
               cx->index,
               parser->daddr,
               uv_strerror((int)outgoing->result));
        /* Send back a 'Host unreachable' reply. */
        conn_write(incoming, "\5\4\0\1\0\0\0\0\0\0", 10);
        return s_kill;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    /* Don't make assumptions about the offset of sin_port/sin6_port. */
    switch (outgoing->t.addr.sa_family) {
    case AF_INET:
        outgoing->t.addr4.sin_port = htons_u(parser->dport);
        break;
    case AF_INET6:
        outgoing->t.addr6.sin6_port = htons_u(parser->dport);
        break;
    default:
        UNREACHABLE();
    }

    return do_req_connect_start(cx);
}

/* Assumes that cx->outgoing.t.sa contains a valid AF_INET/AF_INET6 address. */
static int do_req_connect_start(client_ctx *cx) {
    conn *incoming;
    conn *outgoing;
    int err;

    incoming = &cx->incoming;
    outgoing = &cx->outgoing;
    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    err = conn_connect(outgoing);
    if (err != 0) {
        pr_err("[%d] Connect Error: %s", cx->index, uv_strerror(err));
        return do_kill(cx);
    }

    return s_req_connect;
}

static int do_req_connect(client_ctx *cx) {
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;
    char addr_storage[sizeof(*in6)];
    conn *incoming;
    conn *outgoing;
    uint8_t *buf;
    int addrlen;

    incoming = &cx->incoming;
    outgoing = &cx->outgoing;

    if ( outgoing->result != 0 ) {
        pr_err("[%d] Upstream Connection Error: %s",
               cx->index, uv_strerror((int)outgoing->result));
        /* Send a 'Connection refused' reply. */
        conn_write(incoming, "\5\5\0\1\0\0\0\0\0\0", 10);
        return s_kill;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    /* Build and send the reply.  Not very pretty but gets the job done. */
    buf = (uint8_t *) incoming->t.buf;
    /* The RFC mandates that the SOCKS server must include the local port
     * and address in the reply.  So that's what we do.
     */
    addrlen = sizeof(addr_storage);
    CHECK(0 == uv_tcp_getsockname(&outgoing->handle.tcp,
                                  (struct sockaddr *) addr_storage,
                                  &addrlen));
    buf[0] = 5;  /* Version. */
    buf[1] = 0;  /* Success. */
    buf[2] = 0;  /* Reserved. */
    if (addrlen == sizeof(*in)) {
        buf[3] = 1;  /* IPv4. */
        in = (const struct sockaddr_in *) &addr_storage;
        memcpy(buf + 4, &in->sin_addr, 4);
        memcpy(buf + 8, &in->sin_port, 2);
        conn_write(incoming, buf, 10);
    } else if (addrlen == sizeof(*in6)) {
        buf[3] = 4;  /* IPv6. */
        in6 = (const struct sockaddr_in6 *) &addr_storage;
        memcpy(buf + 4, &in6->sin6_addr, 16);
        memcpy(buf + 20, &in6->sin6_port, 2);
        conn_write(incoming, buf, 22);
    } else {
        UNREACHABLE();
    }

    desc_tcp_proxy_link(cx);
    pr_info("[%d] Connected [%s]", cx->index, cx->link_info);

    return s_proxy_start;
}

static int do_proxy_start(client_ctx *cx) {
    conn *incoming;
    conn *outgoing;

    incoming = &cx->incoming;
    outgoing = &cx->outgoing;

    if ( incoming->result < 0 ) {
        pr_err("[%d] Proxy Start Write Error: %s [%s]",
               cx->index, uv_strerror((int)incoming->result), cx->link_info);
        return do_kill(cx);
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);
    incoming->wrstate = c_stop;

    conn_read(incoming);
    conn_read(outgoing);
    return s_proxy;
}

/* Proxy incoming data back and forth. */
static int do_proxy(client_ctx *cx) {
    if (conn_cycle("client", &cx->incoming, &cx->outgoing)) {
        return do_kill(cx);
    }

    if (conn_cycle("upstream", &cx->outgoing, &cx->incoming)) {
        return do_kill(cx);
    }

    return s_proxy;
}


static int do_udp_response(client_ctx *cx) {
    conn *incoming;
    s5_ctx *parser;
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len;
    char *p;
    void *p_addr;
    unsigned short port;

    parser = &cx->parser;
    incoming = &cx->incoming;

    /* Obtain udp client ip && port, just query it from tcp socket */
    memset(&s, 0, sizeof(s));
    addr_len = sizeof(s);
    CHECK(0 == uv_tcp_getpeername(
        &incoming->handle.tcp,
        (struct sockaddr *)&s,
        &addr_len));
    /* Overwrite port */
    if ( s.addr.sa_family == AF_INET ) s.addr4.sin_port = htons_u(parser->dport);
    if ( s.addr.sa_family == AF_INET6 ) s.addr6.sin6_port = htons_u(parser->dport);

    /* Create client endpoint if necessary */
    CHECK(NULL != client_endpoint_add(cx, &s.addr));


    /* Obtain proxy addr && port, sendback to client */
    memset(&s, 0, sizeof(s));
    addr_len = sizeof(s);
    CHECK(0 == uv_tcp_getsockname(
        &incoming->handle.tcp,
        (struct sockaddr *)&s,
        &addr_len));
    p_addr = s.addr.sa_family == AF_INET ? (void*)&s.addr4.sin_addr : (void*)&s.addr6.sin6_addr;
    addr_len = s.addr.sa_family == AF_INET ? sizeof(s.addr4.sin_addr) : sizeof(s.addr6.sin6_addr);
    port = s.addr.sa_family == AF_INET6 ? s.addr4.sin_port : s.addr6.sin6_port;

    /* struct s5 pkt */
    p = cx->incoming.t.buf;
    *p++ = (char)'\5';
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = s.addr.sa_family == AF_INET ? (char)'\1' : (char)'\4';

    memcpy(p, p_addr, addr_len);
    p += addr_len;

    memcpy(p, &port, sizeof(port));
    p += sizeof(port);

    desc_tcp_proxy_link(cx);
    pr_info("[%d] Create UDP Proxy Link [%s]", cx->index, cx->link_info);

    conn_write(incoming, incoming->t.buf, (unsigned int)(p - incoming->t.buf));

    return s_udp_proxy_start;
}

static int do_udp_proxy_start(client_ctx *cx) {

    conn *incoming;

    incoming = &cx->incoming;

    if ( incoming->result < 0 )
    {
        pr_err("[%d] Client Endpoint Write Error: %s [%s]",
               cx->index, uv_strerror((int)incoming->result), cx->link_info);
        return do_kill(cx);
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    incoming->wrstate = c_stop;

    /* Wait EOF */
    conn_read(incoming);

    return s_udp_proxy_until;
}

static int do_udp_proxy_stop(client_ctx *cx) {
    conn *incoming;

    incoming = &cx->incoming;

    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    /* It should be EOF or a read error or timer expire */
    ASSERT(incoming->result < 0);

    return do_kill(cx);
}

static int do_kill(client_ctx *cx) {
    int new_state = s_almost_dead_1;

    if ( cx->outstanding != 0 ) {
        /* Wait for uncomplete write operation */
        pr_warn("[%d] Waitting outstanding operation, current %d [%s]",
                cx->index, cx->outstanding, cx->link_info);
        return s_kill;
    }


    if (cx->state >= s_almost_dead_0) {
        return cx->state;
    }

    conn_close(&cx->incoming);
    conn_close(&cx->outgoing);
    return new_state;
}

static int do_almost_dead(client_ctx *cx) {
    ASSERT(cx->state >= s_almost_dead_0);
    return cx->state + 1;  /* Another finalizer completed. */
}

static int conn_cycle(const char *who, conn *a, conn *b) {
    if (a->result < 0) {
        if (a->result != UV_EOF) {
            pr_err("[%d] %s error: %s [%s]",
                   a->client->index, who, uv_strerror((int)a->result), a->client->link_info);
        }
        return -1;
    }

    if (b->result < 0) {
        return -1;
    }

    if (a->wrstate == c_done) {
        a->wrstate = c_stop;
    }

    /* The logic is as follows: read when we don't write and write when we don't
     * read.  That gives us back-pressure handling for free because if the peer
     * sends data faster than we consume it, TCP congestion control kicks in.
     */
    if (a->wrstate == c_stop) {
        if (b->rdstate == c_stop) {
            conn_read(b);
        } else if (b->rdstate == c_done) {
            conn_write(a, b->t.buf, (unsigned int)b->result);
            b->rdstate = c_stop;  /* Triggers the call to conn_read() above. */
        }
    }

    return 0;
}

static void conn_timer_reset(conn *c) {
    CHECK(0 == uv_timer_start(&c->timer_handle,
                              conn_timer_expire,
                              c->idle_timeout,
                              0));
}

static void conn_timer_expire(uv_timer_t *handle) {
    conn *c;
    conn *incoming;
    conn *outgoing;

    c = CONTAINER_OF(handle, conn, timer_handle);
    incoming = &c->client->incoming;
    outgoing = &c->client->outgoing;

    switch ( c->client->state ) {
    case s_handshake:
    case s_auth_start:
    case s_handshake_auth:
    case s_req_start:
    case s_req_parse:

    case s_udp_proxy_start:
    case s_udp_proxy_until:
        ASSERT(c == incoming);
        incoming->result = UV_ETIMEDOUT;
        break;

    case s_req_lookup:
    case s_req_connect:
        outgoing->result = UV_ETIMEDOUT;

    case s_proxy_start:
        incoming->result = UV_ETIMEDOUT;
        break;

    default:
        c->result = UV_ETIMEDOUT;
        break;
    }

    do_next(c->client);
}

static void conn_getaddrinfo(conn *c, const char *hostname) {
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    CHECK(0 == uv_getaddrinfo(c->client->sx->loop,
                              &c->t.addrinfo_req,
                              conn_getaddrinfo_done,
                              hostname,
                              NULL,
                              &hints));
    c->client->outstanding++;
    conn_timer_reset(c);
}

static void conn_getaddrinfo_done(uv_getaddrinfo_t *req,
    int status,
    struct addrinfo *ai) {
    conn *c;

    c = CONTAINER_OF(req, conn, t.addrinfo_req);
    c->result = status;

    if (status == 0) {
        /* FIXME(bnoordhuis) Should try all addresses. */
        if (ai->ai_family == AF_INET) {
            c->t.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        } else if (ai->ai_family == AF_INET6) {
            c->t.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        } else {
            UNREACHABLE();
        }
    }

    uv_freeaddrinfo(ai);

    c->client->outstanding--;
    do_next(c->client);
}

/* Assumes that c->t.sa contains a valid AF_INET or AF_INET6 address. */
static int conn_connect(conn *c) {
    ASSERT(c->t.addr.sa_family == AF_INET ||
           c->t.addr.sa_family == AF_INET6);
    conn_timer_reset(c);
    CHECK(0 == uv_tcp_connect(&c->t.connect_req,
                              &c->handle.tcp,
                              &c->t.addr,
                              conn_connect_done));
    c->client->outstanding++;
    return 0;
}

static void conn_connect_done(uv_connect_t *req, int status) {
    conn *c;

    c = CONTAINER_OF(req, conn, t.connect_req);
    c->result = status;

    c->client->outstanding--;
    do_next(c->client);
}

static void conn_read(conn *c) {
    ASSERT(c->rdstate == c_stop);
    CHECK(0 == uv_read_start(&c->handle.stream, conn_alloc, conn_read_done));
    c->rdstate = c_busy;
    conn_timer_reset(c);
}

static void conn_read_done(uv_stream_t *handle,
    ssize_t nread,
    const uv_buf_t *buf) {
    conn *c;

    c = CONTAINER_OF(handle, conn, handle);
    ASSERT(c->t.buf == buf->base);
    ASSERT(c->rdstate == c_busy);
    c->rdstate = c_done;
    c->result = nread;

    uv_read_stop(&c->handle.stream);
    do_next(c->client);
}

static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {

    (void)size;
    conn *c;

    c = CONTAINER_OF(handle, conn, handle);
    ASSERT(c->rdstate == c_busy);
    buf->base = c->t.buf;
    buf->len = sizeof(c->t.buf);
}

static void conn_write(conn *c, const void *data, unsigned int len) {
    uv_buf_t buf;

    ASSERT(c->wrstate == c_stop || c->wrstate == c_done);
    c->wrstate = c_busy;

    /* It's okay to cast away constness here, uv_write() won't modify the
     * memory.
     */
    buf.base = (char *) data;
    buf.len = len;

    CHECK(0 == uv_write(&c->write_req,
                        &c->handle.stream,
                        &buf,
                        1,
                        conn_write_done));
    c->client->outstanding++;
    conn_timer_reset(c);
}

static void conn_write_done(uv_write_t *req, int status) {
    conn *c;

    c = CONTAINER_OF(req, conn, write_req);
    c->client->outstanding--;
    ASSERT(c->wrstate == c_busy);
    c->wrstate = c_done;
    c->result = status;
    do_next(c->client);
}

static void conn_close(conn *c) {
    ASSERT(c->rdstate != c_dead);
    ASSERT(c->wrstate != c_dead);
    c->rdstate = c_dead;
    c->wrstate = c_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;
    uv_close(&c->handle.handle, conn_close_done);
    uv_close((uv_handle_t *) &c->timer_handle, conn_close_done);
}

static void conn_close_done(uv_handle_t *handle) {
    conn *c;

    c = handle->data;
    do_next(c->client);
}


static client_endpoint *client_endpoint_add(client_ctx *cx, struct sockaddr *addr) {
    client_endpoint *cp;

    CHECK(NULL == client_endpoint_find(cx->sx, addr));

    /* Add new client endpoint node */
    cp = xmalloc(sizeof(*cp));
    cp->cx = cx;
    cp->sp = NULL;
    cp->next = cx->sx->cp_link;
    cx->sx->cp_link = cp;
    cx->cp = cp;

    if ( addr->sa_family == AF_INET ) {
        cp->client.addr4 = *(struct sockaddr_in*)addr;
    }
    else if ( addr->sa_family == AF_INET6 ) {
        cp->client.addr6 = *(struct sockaddr_in6*)addr;
    }
    else {
        UNREACHABLE();
    }

    return cp;
}

static server_endpoint *server_endpoint_add(client_endpoint *cp, struct sockaddr *addr) {
    server_endpoint *sp;

    sp = server_endpoint_find(cp, addr);
    if ( sp )
        return sp;

    /* Add new server endpoint node */
    sp = xmalloc(sizeof(*sp));
    sp->cp = cp;
    sp->next = cp->sp;
    cp->sp = sp;

    CHECK(0 == uv_udp_init(cp->cx->sx->loop, &sp->handle));
    CHECK(0 == uv_udp_recv_start(
        &sp->handle, server_endpoint_alloc_cb, server_endpoint_read_done));

    if ( addr->sa_family == AF_INET ) {
        sp->server.addr4 = *(struct sockaddr_in*)addr;
    }
    else if ( addr->sa_family == AF_INET6 ) {
        sp->server.addr6 = *(struct sockaddr_in6*)addr;
    }
    else {
        UNREACHABLE();
    }

    return sp;
}


static client_endpoint *client_endpoint_find(server_ctx *sx, struct sockaddr *addr) {
    client_endpoint *cp;
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;

    cp = sx->cp_link;
    while ( cp ) {
        if ( cp->client.addr.sa_family == addr->sa_family ) {
            if ( addr->sa_family == AF_INET ) {

                in = (struct sockaddr_in*)addr;

                if ( in->sin_port == cp->client.addr4.sin_port &&
                     0 == memcmp(
                         &in->sin_addr,
                         &cp->client.addr4.sin_addr,
                         sizeof(in->sin_addr)) )
                    break;
            }
            else if ( addr->sa_family == AF_INET6 ) {

                in6 = (struct sockaddr_in6*)addr;

                if ( in6->sin6_port == cp->client.addr6.sin6_port &&
                     0 == memcmp(
                         &in6->sin6_addr,
                         &cp->client.addr6.sin6_addr,
                         sizeof(in6->sin6_addr)) )
                    break;
            }
            else {
                UNREACHABLE();
            }
        }

        cp = cp->next;
    }

    return cp;
}

static server_endpoint *server_endpoint_find(client_endpoint *cp, struct sockaddr *addr) {
    server_endpoint *sp;
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;

    sp = cp->sp;
    while ( sp ) {
        if ( sp->server.addr.sa_family == addr->sa_family ) {
            if ( addr->sa_family == AF_INET ) {

                in = (struct sockaddr_in *)addr;

                if ( in->sin_port == sp->server.addr4.sin_port &&
                     0 == memcmp(
                         &in->sin_addr,
                         &sp->server.addr4.sin_addr,
                         sizeof(in->sin_addr)))
                    break;
            }
            else if ( addr->sa_family == AF_INET6 ) {

                in6 = (struct sockaddr_in6*)addr;

                if ( in6->sin6_port == sp->server.addr6.sin6_port &&
                     0 == memcmp(
                         &in6->sin6_addr,
                         &sp->server.addr6.sin6_addr,
                         sizeof(in6->sin6_addr)) )
                    break;
            }
            else {
                UNREACHABLE();
            }
        }
        sp = sp->next;
    }

    return sp;
}

static void client_endpoint_del(server_ctx *sx, client_endpoint *cp) {
    client_endpoint *cp_cur, *cp_pre;
    server_endpoint *sp_cur;

    if ( DEBUG_CHECKS )
        CHECK(cp == client_endpoint_find(sx, &cp->client.addr));

    cp_cur = sx->cp_link;
    cp_pre = NULL;
    while ( cp_cur ) {

        if ( cp_cur == cp ) {
            if ( cp_pre ) {
                cp_pre->next = cp_cur->next;
            } else {
                sx->cp_link = cp_cur->next;
            }

            break;
        }

        cp_pre = cp_cur;
        cp_cur = cp_cur->next;
    }

    sp_cur = cp->sp;
    while ( sp_cur ) {
        uv_udp_recv_stop(&sp_cur->handle);
        uv_close((uv_handle_t *)&sp_cur->handle, server_endpoint_close_done);
        sp_cur = sp_cur->next;
    }
    cp->sp = NULL;

    if ( DEBUG_CHECKS) {
        memset(cp, -1, sizeof(*cp));
    }
    free(cp);
}

static void server_endpoint_close_done(uv_handle_t *handle) {
    server_endpoint *sp;

    sp = CONTAINER_OF(handle, server_endpoint, handle);

    if ( DEBUG_CHECKS) {
        memset(sp, -1, sizeof(*sp));
    }
    free(sp);
}


/* Recv packet from client */
void client_endpoint_read_done(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {

    server_ctx *sx;
    client_ctx *cx;
    client_endpoint *cp;
    uint8_t *data_pos;
    size_t data_len;
    s5_ctx *parser;
    struct addrinfo hints;
    static server_endpoint_param param;
    s5_err err;

    (void)flags;

    /* handle is listening udp socket */
    sx = CONTAINER_OF(handle, server_ctx, udp_handle);

    if ( 0 > nread ) {
        pr_err("Client Endpoint Read Error: %s", uv_strerror((int)nread));
        return;
    }

    if ( 0 == nread ) {
        /* nothing to read or recved an empty packet */
        return ;
    }

    /* Handshake auth success already? */
    cp = client_endpoint_find(sx, (struct sockaddr *)addr);
    ASSERT(cp);
    cx = cp->cx;

    data_pos = (uint8_t*)buf->base;
    data_len = (size_t)nread;

    parser = &cx->parser;
    /* parse s5 packet */
    err = s5_parse_udp(parser, &data_pos, &data_len);
    if ( s5_exec_cmd != err ) {
        pr_err("[%d] S5 UDP Parse Error: %s [%s]", cx->index, s5_strerror(err), cx->link_info);
        return ;
    }

    param.cp = cp;
    param.data = (const char*)data_pos;
    param.data_len = data_len;

    if (parser->atyp == s5_atyp_host) {

        /* TODO: DNS CACHE */

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        CHECK(0 == uv_getaddrinfo(sx->loop,
                                  &param.r.getaddr_req,
                                  client_endpoint_getaddr_done,
                                  (const char *)parser->daddr,
                                  NULL,
                                  &hints));

        conn_timer_reset(&cx->incoming);
        /* Stop recv until send data out or error occur */
        uv_udp_recv_stop(handle);
        return ;
    }

    if ( parser->atyp == s5_atyp_ipv4 ) {
        param.s.addr4.sin_family = AF_INET;
        param.s.addr4.sin_port = htons_u(parser->dport);
        memcpy(&param.s.addr4.sin_addr, parser->daddr, sizeof(param.s.addr4.sin_addr));

    } else if (parser->atyp == s5_atyp_ipv6) {
        param.s.addr6.sin6_family = AF_INET6;
        param.s.addr6.sin6_port = htons_u(parser->dport);
        memcpy(&param.s.addr6.sin6_addr, parser->daddr, sizeof(param.s.addr6.sin6_addr));
    } else {
        UNREACHABLE();
    }
    /* Stop recv until send data out or error occur */
    uv_udp_recv_stop(handle);
    send_to_server_endpoint(&param);
}

void client_endpoint_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    (void)suggested_size;
    static char slab[MAX_UDP_PAYLOAD_LEN];

    buf->base = slab;
    buf->len = sizeof(slab);
}


static void client_endpoint_getaddr_done(
    uv_getaddrinfo_t *req,
    int status,
    struct addrinfo *ai) {

    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
    server_endpoint_param *param = CONTAINER_OF(req, server_endpoint_param, r.getaddr_req);

    if ( status == 0 ) {
        if (ai->ai_family == AF_INET) {
            in = (struct sockaddr_in*)ai->ai_addr;
            param->s.addr4.sin_family = AF_INET;
            param->s.addr4.sin_port = htons_u(param->cp->cx->parser.dport);     /* parser.dport as host byte order */
            memcpy(&param->s.addr4.sin_addr, &in->sin_addr, sizeof(in->sin_addr));

        } else if (ai->ai_family == AF_INET6) {
            in6 = (struct sockaddr_in6*)ai->ai_addr;
            param->s.addr6.sin6_family = AF_INET6;
            param->s.addr6.sin6_port = htons_u(param->cp->cx->parser.dport);   /* parser.dport as host byte order */
            memcpy(&param->s.addr6.sin6_addr, &in6->sin6_addr, sizeof(in6->sin6_addr));

        } else {
            UNREACHABLE();
        }

        send_to_server_endpoint(param);
    } else {
        pr_err("[%d] Client Endpoint getaddr Error: %s for %s [%s]",
               param->cp->cx->index,
               uv_strerror(status), param->cp->cx->parser.daddr, param->cp->cx->link_info);
        uv_udp_recv_start(
            &param->cp->cx->sx->udp_handle,
            client_endpoint_alloc_cb,
            client_endpoint_read_done);
    }

    freeaddrinfo(ai);
}

static void send_to_server_endpoint(server_endpoint_param *param) {
    server_endpoint *sp;
    client_ctx *cx;
    uv_buf_t buf;

    /* Create server endpoint if necessary */
    sp = server_endpoint_find(param->cp, &param->s.addr);
    if ( !sp ) {
        sp = server_endpoint_add(param->cp, &param->s.addr);
        ASSERT(sp);

        cx = sp->cp->cx;
        desc_udp_endpoint_link(cx, sp);
        pr_info("[%d] Create UDP Endpoint Link [%s]", cx->index, sp->link_info);
    }

    buf = uv_buf_init((char*)param->data, (unsigned int)param->data_len);

    if ( 0 != uv_udp_send(&param->r.send_req,
                          &sp->handle,
                          &buf,
                          1,
                          &sp->server.addr,
                          client_endpoint_send_done) ) {
        uv_udp_recv_start(
            &param->cp->cx->sx->udp_handle,
            client_endpoint_alloc_cb,
            client_endpoint_read_done);
    } else {
        conn_timer_reset(&param->cp->cx->incoming);
    }
}

static void client_endpoint_send_done(uv_udp_send_t *req, int status) {
    server_endpoint_param *param;

    param = CONTAINER_OF(req, server_endpoint_param, r.send_req);

    if ( 0 != status ) {
        pr_err("[%d] Client Endpoint Send Error: %d",
               param->cp->cx->index, status);
    }

    uv_udp_recv_start(
        &param->cp->cx->sx->udp_handle,
        client_endpoint_alloc_cb,
        client_endpoint_read_done);
}



/* Recv data from server endpoint */
static void server_endpoint_read_done(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {

    server_endpoint *sp;
    client_endpoint *cp;
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
    uv_buf_t buf_p;
    char *p;
    unsigned int offset;

    (void)flags;

    sp = CONTAINER_OF(handle, server_endpoint, handle);
    cp = sp->cp;

    if ( 0 > nread ) {
        pr_err("[%d] Server Endpoint Read Error: %s [%s]",
               cp->cx->index, uv_strerror((int)nread), sp->link_info);
        return;
    }

    if ( 0 == nread ) {
        /* nothing to read or recved an empty packet */
        return ;
    }


    if ( DEBUG_CHECKS ) {
        ASSERT(addr->sa_family == sp->server.addr.sa_family);
        if ( addr->sa_family == AF_INET ) {
            in = (struct sockaddr_in*)addr;
            CHECK(in->sin_port == sp->server.addr4.sin_port);
            CHECK(0 == memcmp(&in->sin_addr, &sp->server.addr4.sin_addr, sizeof(in->sin_addr)));
        }
        else if ( addr->sa_family == AF_INET6 ) {
            in6 = (struct sockaddr_in6*)addr;
            CHECK(in6->sin6_port == sp->server.addr6.sin6_port);
            CHECK(0 == memcmp(&in6->sin6_addr, &sp->server.addr6.sin6_addr, sizeof(in6->sin6_addr)));
        }
    }

    /* shift to socks5 hdr */
    offset = addr->sa_family == AF_INET ? S5_IPV4_UDP_SEND_HDR_LEN : S5_IPV6_UDP_SEND_HDR_LEN;
    p = buf->base - offset;

    /* s5 hdr */
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = addr->sa_family == AF_INET ? (char)'\1' : (char)'\4';

    /* Write server ip && port to s5 hdr */
    if ( addr->sa_family == AF_INET ) {
        in = (struct sockaddr_in*)addr;
        memcpy(p, &in->sin_addr, sizeof(in->sin_addr));
        p += sizeof(in->sin_addr);
        memcpy(p, &in->sin_port, sizeof(in->sin_port));
    }
    else if ( addr->sa_family == AF_INET6 ) {
        in6 = (struct sockaddr_in6*)addr;
        memcpy(p, &in6->sin6_addr, sizeof(in6->sin6_addr));
        p += sizeof(in6->sin6_addr);
        memcpy(p, &in6->sin6_port, sizeof(in6->sin6_port));
    }

    buf_p = uv_buf_init(buf->base - offset, (unsigned int)nread + offset);
    if ( 0 == uv_udp_send(&sp->send_req,
                          &cp->cx->sx->udp_handle,
                          &buf_p,
                          1,
                          &cp->client.addr,
                          server_endpoint_send_done) ) {
        conn_timer_reset(&sp->cp->cx->incoming);
        uv_udp_recv_stop(handle);
    }
}


static void server_endpoint_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    server_endpoint *sp;

    (void)suggested_size;
    sp = CONTAINER_OF(handle, server_endpoint, handle);

    /* Leave space for socks5 head */
    buf->base = sp->buf + MAX_S5_UDP_SEND_HDR_LEN;
    buf->len = sizeof(sp->buf) - MAX_S5_UDP_SEND_HDR_LEN;
}


static void server_endpoint_send_done(uv_udp_send_t *req, int status) {
    server_endpoint *sp;

    sp = CONTAINER_OF(req, server_endpoint, send_req);

    if ( 0 != status ) {
        pr_err("[%d] Server Endpoint Send Error: %s [%s]",
               sp->cp->cx->index, uv_strerror(status), sp->link_info);
    }

    uv_udp_recv_start(
        &sp->handle,
        server_endpoint_alloc_cb,
        server_endpoint_read_done);
}

