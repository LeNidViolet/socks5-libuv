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
#include <stdlib.h>
#include "uv.h"
#include "s5.h"
#include "dnsc.h"
#include "uvsocks5/uvsocks5.h"
#include "internal.h"

static unsigned int dn_outstanding = 0;

static int do_handshake(PROXY_NODE *pn);
static int do_req_start(PROXY_NODE *pn);
static int do_req_parse(PROXY_NODE *pn);
static int do_req_connect(PROXY_NODE *pn);
static int do_proxy_start(PROXY_NODE *pn);
static int do_proxy(CONN *sender);
static int do_dgram_start(PROXY_NODE *pn);
static int do_dgram_stop(PROXY_NODE *pn);
static int do_req_lookup(PROXY_NODE *pn);
static int do_req_connect_start(PROXY_NODE *pn);
static int do_dgram_response(PROXY_NODE *pn);
static int do_almost_dead(PROXY_NODE *pn);
static int do_clear(PROXY_NODE *pn);

static void dgram_read(uv_udp_t *udp_handle, DGRAM_NODE *dn);
static void dgram_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done(uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
static void dgram_timer_reset(DGRAM_NODE *dn);
static void dgram_read_done_l(uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
static void dgram_read_done_r(uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
static void dgram_write_to_remote(DGRAM_LOCAL *dgraml);
static void dgram_write_to_local(DGRAM_REMOTE *dgramr);
static void dgram_write_done(uv_udp_send_t* req, int status);
static void dgram_timer_expire(uv_timer_t *handle);
static void dgram_tear_down(DGRAM_NODE *dn);
static void dgram_close_done(uv_handle_t* handle);
static void dgram_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);


void do_next(CONN *sender) {
    PROXY_NODE *pn;
    int new_state = s_max;

    pn = sender->pn;

    ASSERT(pn->state != s_dead);
    switch (pn->state) {
    case s_handshake:
        new_state = do_handshake(pn);
        break;
    case s_req_start:
        new_state = do_req_start(pn);
        break;
    case s_req_parse:
        new_state = do_req_parse(pn);
        break;
    case s_req_lookup:
        new_state = do_req_lookup(pn);
        break;
    case s_req_connect:
        new_state = do_req_connect(pn);
        break;
    case s_dgram_start:
        new_state = do_dgram_start(pn);
        break;
    case s_dgram_stop:
        new_state = do_dgram_stop(pn);
        break;
    case s_proxy_start:
        new_state = do_proxy_start(pn);
        break;
    case s_proxy:
        new_state = do_proxy(sender);
        break;
    case s_kill:
        new_state = do_kill(pn);
        break;
    case s_almost_dead_0:
    case s_almost_dead_1:
    case s_almost_dead_2:
    case s_almost_dead_3:
    case s_almost_dead_4:
        new_state = do_almost_dead(pn);
        break;
    default:
        UNREACHABLE();
    }
    pn->state = new_state;

    if ( pn->state == s_dead )
        do_clear(pn);
}

static int do_handshake(PROXY_NODE *pn) {
    CONN *incoming;
    int new_state, err;
    uint8_t *data_pos;
    size_t data_len;
    unsigned int methods;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        notify_msg_out(1, "[%d] Handshake read error: %s",
                       pn->index, uv_strerror((int)incoming->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    data_pos = (uint8_t *)incoming->us_buf.buf_base,
    data_len = (size_t)incoming->result;
    err = s5_parse(&pn->parser, &data_pos, &data_len);
    if ( s5_ok == err ) {
        conn_read(incoming);
        new_state = s_req_parse;
        BREAK_NOW;
    }

    if ( data_len != 0 ) {
        notify_msg_out(1, "[%d] Junk in equest %u", pn->index, (unsigned)data_len);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( err != s5_auth_select ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    methods = s5_auth_methods(&pn->parser);
    if ( methods & (unsigned int)S5_AUTH_NONE ) {
        s5_select_auth(&pn->parser, S5_AUTH_NONE);
        conn_write(incoming, "\5\0", 2);  /* No auth required. */
        new_state = s_req_start;
    } else {
        conn_write(incoming, "\5\255", 2);  /* No acceptable auth. */
        new_state = s_kill;
    }

BREAK_LABEL:

    return new_state;
}

static int do_req_start(PROXY_NODE *pn) {
    CONN *incoming;
    int new_state;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    incoming->wrstate = c_stop;

    conn_read(incoming);

    new_state = s_req_parse;

BREAK_LABEL:

    return new_state;
}

static int do_req_parse(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state, err;
    s5_ctx *parser;
    uint8_t *data_pos;
    size_t data_len;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( incoming->result < 8 ) {  /* |VER|CMD|RSV|ATYP|DST.ADDR|DST.PORT|DATA */
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);
    incoming->rdstate = c_stop;

    parser = &pn->parser;
    data_pos = (uint8_t *)incoming->us_buf.buf_base;
    data_len = (size_t)incoming->result;
    err = s5_parse(parser, &data_pos, &data_len);
    if ( s5_ok == err ) {
        conn_read(incoming);
        new_state = s_req_parse;
        BREAK_NOW;
    }

    if ( 0 != data_len ) {
        notify_msg_out(1, "[%d] Junk in equest %u", pn->index, (unsigned)data_len);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( s5_exec_cmd != err ) {
        notify_msg_out(1, "[%d] Request error: %s", pn->index, s5_strerror((s5_err)err));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( s5_cmd_tcp_bind == parser->cmd ) {
        /* Not supported */
        notify_msg_out(1, "[%d] Bind requests are not supported.", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( s5_cmd_udp_assoc == parser->cmd ) {
        new_state = do_dgram_response(pn);
        BREAK_NOW;
    }

    if ( s5_cmd_tcp_connect != parser->cmd ) {
        notify_msg_out(1, "[%d] Unknow s5 command %d.", pn->index, parser->cmd);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    s5_addr_copy(parser, &outgoing->t.addr, &outgoing->peer);

    if ( parser->atyp == s5_atyp_host ) {
        conn_getaddrinfo(outgoing, (const char *)parser->daddr);
        new_state = s_req_lookup;
        BREAK_NOW;
    }

    new_state = do_req_connect_start(pn);

BREAK_LABEL:

    return new_state;
}

static int do_req_lookup(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        notify_msg_out(1, "[%d] Lookup Error For %s : %s",
                       pn->index,
                       outgoing->peer.host,
                       uv_strerror((int)outgoing->result));

        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    ret = do_req_connect_start(pn);

BREAK_LABEL:

    return ret;
}

static int do_req_connect_start(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int err, new_state;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;
    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    err = conn_connect(outgoing);
    if ( err != 0 ) {
        notify_msg_out(1, "[%d] Connect error: %s", pn->index, uv_strerror(err));
        new_state = do_kill(pn);
    } else {
        new_state = s_req_connect;
    }

    return new_state;
}

static int do_req_connect(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state;
    int addrlen;
    char addr_storage[sizeof(struct sockaddr_in6)];
    static char ipv4_reply[] = { "\5\0\0\1\0\0\0\0\16\16" };
    static char ipv6_reply[] = { "\5\0\0\4"
                                 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                 "\10\10" };

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result != 0 ) {
        notify_msg_out(
            1,
            "[%d] Connect %s:%d error: %s",
            pn->index,
            outgoing->peer.host,
            outgoing->peer.port,
            uv_strerror((int)outgoing->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    notify_connection_made(pn);

    snprintf(pn->link_info, sizeof(pn->link_info), "%s:%d -> %s:%d",
             incoming->peer.host,
             incoming->peer.port,
             outgoing->peer.host,
             outgoing->peer.port);

    addrlen = sizeof(addr_storage);
    if ( 0 != uv_tcp_getsockname(&outgoing->handle.tcp,
                                 (struct sockaddr *) addr_storage,
                                 &addrlen) ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if (addrlen == sizeof(struct sockaddr_in)) {
        conn_write(incoming, ipv4_reply, 10);
    } else if (addrlen == sizeof(struct sockaddr_in6)) {
        conn_write(incoming, ipv6_reply, 22);
    } else {
        UNREACHABLE();
    }

    new_state = s_proxy_start;

BREAK_LABEL:

    return new_state;
}

static int do_proxy_start(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( incoming->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);
    incoming->wrstate = c_stop;

    conn_read(incoming);
    conn_read(outgoing);

    new_state = s_proxy;

BREAK_LABEL:

    return new_state;
}

/* Proxy incoming data back and forth. */
static int do_proxy(CONN *sender) {
    int new_state;
    CONN *incoming;
    CONN *outgoing;

    incoming = &sender->pn->incoming;
    outgoing = &sender->pn->outgoing;

    if ( c_done == sender->rdstate && sender->result > 0 ) {

        handle_plain_stream(sender);
    }

    if ( conn_cycle("client", incoming, outgoing) ) {
        new_state = do_kill(incoming->pn);
        BREAK_NOW;
    }

    if ( conn_cycle("upstream", outgoing, incoming) ) {
        new_state = do_kill(incoming->pn);
        BREAK_NOW;
    }

    new_state = s_proxy;

BREAK_LABEL:

    return new_state;
}

int do_kill(PROXY_NODE *pn) {
    int new_state;

    if ( pn->outstanding != 0 ) {
        /* Wait for uncomplete operations */
        notify_msg_out(
            2,
            "[%d] Waitting outstanding operation: %d [%s]",
            pn->index, pn->outstanding, pn->link_info);
        new_state = s_kill;
        BREAK_NOW;
    }

    if ( pn->state >= s_almost_dead_0 ) {
        new_state = pn->state;
        BREAK_NOW;
    }

    if ( pn->dn ) {
        if ( pn->dn->pn )
            pn->dn->pn = NULL;
        dgram_tear_down(pn->dn);
        pn->dn = NULL;
    }

    conn_close(&pn->incoming);
    conn_close(&pn->outgoing);

    new_state = s_almost_dead_1;

BREAK_LABEL:

    return new_state;
}

static int do_almost_dead(PROXY_NODE *pn) {
    ASSERT(pn->state >= s_almost_dead_0);
    return pn->state + 1;  /* Another finalizer completed. */
}

static int do_clear(PROXY_NODE *pn) {
    handle_stream_teardown(pn);

    if ( DEBUG_CHECKS ) {
        memset(pn, -1, sizeof(*pn));
    }
    free(pn);

    pn_outstanding--;
    if ( 0 == pn_outstanding )
        printf("PN OUTSTANDING BACK TO ZERO\n");

    return 0;
}

static int do_dgram_response(PROXY_NODE *pn) {
    int ret;
    CONN *incoming;
    DGRAM_NODE *dn;
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len;
    void *p_addr;
    unsigned short port;
    char *p;

    incoming = &pn->incoming;
    ENSURE((dn = malloc(sizeof(*dn))) != NULL);
    memset(dn, 0, sizeof(*dn));
    CHECK(0 == uv_udp_init(pn->loop, &dn->incoming.handle.udp));
    CHECK(0 == uv_udp_init(pn->loop, &dn->outgoing.handle.udp));
    CHECK(0 == uv_timer_init(pn->loop, &dn->timer));
    uv_handle_set_data(&dn->incoming.handle.handle, &dn->incoming);
    uv_handle_set_data(&dn->outgoing.handle.handle, &dn->outgoing);
    uv_handle_set_data((uv_handle_t*)&dn->timer, dn);
    dn->incoming.dn = dn;
    dn->outgoing.dn = dn;
    dn->incoming.us_buf.buf_base = dn->incoming.slab;
    dn->incoming.us_buf.buf_len = sizeof(dn->incoming.slab);
    dn->outgoing.us_buf.buf_base = dn->outgoing.slab;
    dn->outgoing.us_buf.buf_len = sizeof(dn->outgoing.slab);
    dn->state = u_using;

    memset(&s, 0, sizeof(s));
    addr_len = sizeof(s);
    CHECK(0 == uv_tcp_getsockname(
        &incoming->handle.tcp,
        (struct sockaddr *)&s,
        &addr_len));

    if ( s.addr.sa_family == AF_INET ) s.addr4.sin_port = 0;
    if ( s.addr.sa_family == AF_INET6 ) s.addr6.sin6_port = 0;

    /* Random choice a port */
    CHECK(0 == uv_udp_bind(&dn->incoming.handle.udp, &s.addr, 0));
    CHECK(0 == uv_udp_getsockname(
        &dn->incoming.handle.udp,
        (struct sockaddr *)&s,
        &addr_len));
    p_addr = s.addr.sa_family ==
             AF_INET ? (void*)&s.addr4.sin_addr : (void*)&s.addr6.sin6_addr;
    addr_len = s.addr.sa_family ==
               AF_INET ? sizeof(s.addr4.sin_addr) : sizeof(s.addr6.sin6_addr);
    port = s.addr.sa_family ==
           AF_INET6 ? s.addr4.sin_port : s.addr6.sin6_port;

    /* Tell socks5 app udp adderss */
    /* struct s5 pkt */
    p = incoming->us_buf.buf_base;
    *p++ = (char)'\5';
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = s.addr.sa_family == AF_INET ? (char)'\1' : (char)'\4';

    memcpy(p, p_addr, addr_len);
    p += addr_len;

    memcpy(p, &port, sizeof(port));
    p += sizeof(port);

    /* associate tcp && udp */
    pn->dn = dn;
    dn->pn = pn;
    conn_write(incoming, incoming->us_buf.buf_base, (unsigned int)(p - incoming->us_buf.buf_base));

    dn_outstanding++;

    ret = s_dgram_start;

BREAK_LABEL:

    return ret;
}

static int do_dgram_start(PROXY_NODE *pn) {
    CONN *incoming;
    int ret;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    incoming->wrstate = c_stop;

    /* Wait EOF */
    conn_read(incoming);

    ret = s_dgram_stop;

    dgram_read(&pn->dn->incoming.handle.udp, pn->dn);
    dgram_read(&pn->dn->outgoing.handle.udp, pn->dn);

BREAK_LABEL:

    return ret;
}

static int do_dgram_stop(PROXY_NODE *pn) {
    CONN *incoming;

    incoming = &pn->incoming;

    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    /* It should be EOF or read error or timer expire */
    ASSERT(incoming->result < 0);

    return do_kill(pn);
}

static void dgram_read(uv_udp_t *udp_handle, DGRAM_NODE *dn) {
    if ( 0 == uv_udp_recv_start(
        udp_handle,
        dgram_alloc_cb,
        dgram_read_done) ) {

        dgram_timer_reset(dn);
        conn_timer_reset(&dn->pn->incoming);
    }
}

static void dgram_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    void *p, *op;
    DGRAM_LOCAL *dgraml;
    DGRAM_REMOTE *dgramr;

    (void)suggested_size;

    p = uv_handle_get_data(handle);
    op = CONTAINER_OF(handle, DGRAM_LOCAL, handle.udp);
    if ( op == p ) {
        dgraml = (DGRAM_LOCAL *)p;
        dgraml->us_buf.buf_base = dgraml->slab;
        dgraml->us_buf.buf_len = sizeof(dgraml->slab);
        buf->base = dgraml->slab;
        buf->len = sizeof(dgraml->slab);
    } else {
        dgramr = (DGRAM_REMOTE *)p;
        dgramr->us_buf.buf_base = dgramr->slab;
        dgramr->us_buf.buf_len = sizeof(dgramr->slab);
        buf->base = dgramr->slab;
        buf->len = sizeof(dgramr->slab);
    }
}

static void dgram_read_done(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {
    void *p, *op;
    int is_local;
    p = uv_handle_get_data((uv_handle_t*)handle);
    op = CONTAINER_OF(handle, DGRAM_LOCAL, handle.udp);

    is_local = p == op;
    if ( is_local ) {
        dgram_read_done_l(handle, nread, buf, addr, flags);
    } else {
        dgram_read_done_r(handle, nread, buf, addr, flags);
    }
}

static void dgram_read_done_l(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {
    DGRAM_LOCAL *dgraml;
    DGRAM_REMOTE *dgramr;
    ADDRESS local = {0};
    ADDRESS remote = {0};
    uint8_t *data_pos;
    size_t data_len;
    s5_ctx parser;
    int err;
    DNSC *dnsc;
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    struct addrinfo hints;

    (void)flags;

    if ( nread == 0 ) {
        BREAK_NOW;
    }

    if ( nread < 0 ) {
        notify_msg_out(1, "Dgram read failed(local): %s", uv_strerror((int)nread));
        BREAK_NOW;
    }

    dgraml = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(dgraml->us_buf.buf_base == buf->base);
    dgramr = &dgraml->dn->outgoing;

    data_pos = (uint8_t*)buf->base;
    data_len = (size_t)nread;

    /* parse s5 packet */
    err = s5_parse_udp(&parser, &data_pos, &data_len);
    if ( s5_exec_cmd != err ) {
        notify_msg_out(1, "[%d] S5 dgram parse error: %s",
                       dgraml->dn->pn->index, s5_strerror(err));
        BREAK_NOW;
    }

    if ( 0 == data_len ) {
        notify_msg_out(1, "[%d] No dgram payload after parse",
                       dgraml->dn->pn->index, s5_strerror(err));
        BREAK_NOW;
    }

    memset(&s, 0, sizeof(s));
    s5_addr_copy(&parser, &s.addr, &remote);

    /* TODO: Dgram client maybe send data to different addresses by the same socket */
    if ( dgramr->peer.port ) {
        if ( dgramr->peer.port != remote.port || 0 != strcmp(dgramr->peer.host, remote.host) ) {
            notify_msg_out(1, "[%d] Dgram one to more detected", dgraml->dn->pn->index);
            BREAK_NOW;
        }
    } else {
        dgramr->peer = remote;
    }

    if ( 0 == dgraml->addr.addr.sa_family ) {
        /* Emit dgram session */
        cpy_sockaddr(addr, &dgraml->addr.addr);
        str_sockaddr(addr, &local);
        handle_new_dgram(&local, &remote, &dgraml->dn->ctx);

        snprintf(dgramr->link_info, sizeof(dgramr->link_info),
            "%s:%d -> %s:%d",
            local.host, local.port,
            remote.host, remote.port);
    } else {
        /* Assume that will no DGRAM from different address */
        if ( 0 != equal_sockaddr(addr, &dgraml->addr.addr) ) {
            notify_msg_out(1, "[%d] Dgram from different local address", dgraml->dn->pn->index);
            BREAK_NOW;
        }
    }

    uv_udp_recv_stop(&dgraml->handle.udp);

    /* Update address range */
    dgraml->us_buf.buf_base = (char*)data_pos;
    dgraml->us_buf.buf_len = data_len;

    if ( 0 == dgramr->addr.addr.sa_family ) {
        if ( parser.atyp == s5_atyp_host ) {

            /* Lookup dns cache */
            dnsc = dnsc_find(remote.host);
            if ( dnsc ) {
                cpy_sockaddr(&dnsc->t.addr, &dgramr->addr.addr);
                set_sockaddr_port(&dgramr->addr.addr, ntohs_u(remote.port));
            } else {
                /* DNS QUERY */
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;

                CHECK(0 == uv_getaddrinfo(uv_handle_get_loop((uv_handle_t*)handle),
                                          &dgramr->req_dns,
                                          dgram_getaddrinfo_done,
                                          remote.host,
                                          NULL,
                                          &hints));
                BREAK_NOW;
            }

        } else {
            cpy_sockaddr(&s.addr, &dgramr->addr.addr);
        }
    }
    /* SEND OUT */
    dgram_write_to_remote(dgraml);

BREAK_LABEL:

    return;
}

static void dgram_read_done_r(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {
    DGRAM_REMOTE *dgramr;
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;
    char *p;
    unsigned int hdr_len;

    (void)flags;

    if ( nread == 0 ) {
        BREAK_NOW;
    }

    if ( nread < 0 ) {
        notify_msg_out(1, "Dgram read failed(remote): %s", uv_strerror((int)nread));
        BREAK_NOW;
    }

    dgramr = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(dgramr->us_buf.buf_base == buf->base);

    /* Address check */
    ASSERT(addr->sa_family == dgramr->addr.addr.sa_family);
    if ( addr->sa_family == AF_INET ) {
        in = (struct sockaddr_in*)addr;
        ASSERT(in->sin_port == dgramr->addr.addr4.sin_port);
        ASSERT(0 == memcmp(&in->sin_addr, &dgramr->addr.addr4.sin_addr, sizeof(in->sin_addr)));
    }
    else if ( addr->sa_family == AF_INET6 ) {
        in6 = (struct sockaddr_in6*)addr;
        ASSERT(in6->sin6_port == dgramr->addr.addr6.sin6_port);
        ASSERT(0 == memcmp(&in6->sin6_addr, &dgramr->addr.addr6.sin6_addr, sizeof(in6->sin6_addr)));
    }

    /* shift to socks5 hdr */
    hdr_len = addr->sa_family == AF_INET ? S5_IPV4_UDP_SEND_HDR_LEN : S5_IPV6_UDP_SEND_HDR_LEN;
    if ( hdr_len + nread > sizeof(dgramr->slab) ) {
        notify_msg_out(1, "Dgram ignore too huge frame, size: %d", nread);
        BREAK_NOW;
    }
    memmove(buf->base + hdr_len, buf->base, nread);

    p = buf->base;
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

    uv_udp_recv_stop(&dgramr->handle.udp);

    dgramr->us_buf.buf_base = buf->base;
    dgramr->us_buf.buf_len = (size_t)(nread + hdr_len);
    dgram_write_to_local(dgramr);

BREAK_LABEL:

    return;
}

static void dgram_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    DGRAM_REMOTE *dgramr;
    DGRAM_LOCAL *dgraml;

    dgramr = CONTAINER_OF(req, DGRAM_REMOTE, req_dns);
    dgraml = &dgramr->dn->incoming;

    if ( status == 0 ) {
        cpy_sockaddr(addrs->ai_addr, &dgramr->addr.addr);
        set_sockaddr_port(&dgramr->addr.addr, ntohs_u(dgramr->peer.port));

        dnsc_add(dgramr->peer.host, addrs->ai_addr);
        dgram_write_to_remote(dgraml);
    } else {
        notify_msg_out(
            1,
            "Dgram getaddrinfo failed: %s, domain: %s",
            uv_strerror(status),
            dgramr->peer.host);

        dgram_read(&dgraml->handle.udp, dgraml->dn);
    }

    uv_freeaddrinfo(addrs);
}

static void dgram_write_to_remote(DGRAM_LOCAL *dgraml) {
    DGRAM_REMOTE *dgramr;
    uv_buf_t buf;

    buf = uv_buf_init(dgraml->us_buf.buf_base, (unsigned int)dgraml->us_buf.buf_len);
    dgramr = &dgraml->dn->outgoing;

    uv_req_set_data((uv_req_t*)&dgramr->req_send, dgramr);
    if ( 0 != uv_udp_send(
        &dgramr->req_send,
        &dgramr->handle.udp,
        &buf,
        1,
        &dgramr->addr.addr,
        dgram_write_done) ) {
        dgram_tear_down(dgramr->dn);
    } else {
        dgram_timer_reset(dgramr->dn);
        conn_timer_reset(&dgramr->dn->pn->incoming);
    }
}

static void dgram_write_to_local(DGRAM_REMOTE *dgramr) {
    DGRAM_LOCAL *dgraml;
    uv_buf_t buf;

    buf = uv_buf_init(dgramr->us_buf.buf_base, (unsigned int)dgramr->us_buf.buf_len);
    dgraml = &dgramr->dn->incoming;

    uv_req_set_data((uv_req_t*)&dgraml->req_send, dgraml);
    if ( 0 != uv_udp_send(
        &dgraml->req_send,
        &dgraml->handle.udp,
        &buf,
        1,
        &dgraml->addr.addr,
        dgram_write_done) ) {
        dgram_tear_down(dgraml->dn);
    } else {
        dgram_timer_reset(dgraml->dn);
        conn_timer_reset(&dgraml->dn->pn->incoming);
    }
}

static void dgram_write_done(uv_udp_send_t* req, int status) {
    DGRAM_LOCAL *dgraml;
    DGRAM_REMOTE *dgramr;
    void *p, *op;

    (void)status;

    p = uv_req_get_data((uv_req_t*)req);
    op = CONTAINER_OF(req, DGRAM_LOCAL, req_send);
    if ( p == op ) {
        dgraml = (DGRAM_LOCAL*)p;
        dgram_read(&dgraml->handle.udp, dgraml->dn);
    } else {
        dgramr = (DGRAM_REMOTE*)p;
        dgram_read(&dgramr->handle.udp, dgramr->dn);
    }
}


static void dgram_timer_reset(DGRAM_NODE *dn) {
    CHECK(0 == uv_timer_start(
        &dn->timer,
        dgram_timer_expire,
        uvsocks5_ctx.config.idel_timeout,
        0));
}

static void dgram_timer_expire(uv_timer_t *handle) {
    DGRAM_NODE *dn;

    dn = uv_handle_get_data((uv_handle_t*)handle);
    dgram_tear_down(dn);
}

static void dgram_tear_down(DGRAM_NODE *dn) {
    if ( dn->state < u_closing0 ) {
        if ( dn->pn ) {
            if ( dn->pn->dn )
                dn->pn->dn = NULL;
            do_kill(dn->pn);
            dn->pn = NULL;
        }

        dn->state = u_closing0;
        uv_close(&dn->incoming.handle.handle, dgram_close_done);
        uv_close(&dn->outgoing.handle.handle, dgram_close_done);
        uv_close((uv_handle_t*)&dn->timer, dgram_close_done);
    }
}

static void dgram_close_done(uv_handle_t* handle) {
    DGRAM_NODE *dn;
    void *p, *op;

    p = uv_handle_get_data(handle);
    op = CONTAINER_OF(handle, DGRAM_LOCAL, handle.handle);
    if ( p == op ) {
        dn = ((DGRAM_LOCAL*)p)->dn;
    } else {
        dn = ((DGRAM_REMOTE*)p)->dn;
    }

    dn->state++;
    if ( u_dead == dn->state ) {
        handle_dgram_teardown(dn->ctx);

        if ( DEBUG_CHECKS )
            memset(dn, 0xff, sizeof(*dn));
        free(dn);

        dn_outstanding--;
        if ( 0 == dn_outstanding )
            printf("DN OUTSTANDING BACK TO ZERO\n");
    }
}
