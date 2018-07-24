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

static void pr_do(FILE *stream,
    const char *label,
    const char *fmt,
    va_list ap);

void *xmalloc(size_t size) {
    void *ptr;

    ptr = malloc(size);
    if (ptr == NULL) {
        pr_err("out of memory, need %lu bytes", (unsigned long) size);
        exit(1);
    }

    return ptr;
}

void pr_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stdout, "info", fmt, ap);
    va_end(ap);
}

void pr_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, "warn", fmt, ap);
    va_end(ap);
}

void pr_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pr_do(stderr, "error", fmt, ap);
    va_end(ap);
}

static void pr_do(FILE *stream,
    const char *label,
    const char *fmt,
    va_list ap) {
  char fmtbuf[1024];
  vsnprintf(fmtbuf, sizeof(fmtbuf), fmt, ap);
  fprintf(stream, "%s:%s: %s\n", _getprogname(), label, fmtbuf);
}


void desc_tcp_proxy_link(client_ctx *cx) {
    conn *incoming;
    conn *outgoing;
    char src[INET6_ADDRSTRLEN + 10];
    char dst[INET6_ADDRSTRLEN + 10];

    incoming = &cx->incoming;
    outgoing = &cx->outgoing;

    memset(src, 0, sizeof(src));
    CHECK(0 == str_tcp_endpoint(&incoming->handle.tcp, peer, src, sizeof(src)));

    if ( cx->parser.atyp == s5_atyp_host ) {
        /* as hostname */
        sprintf(cx->link_info, "%s -> %s:%d", src, cx->parser.daddr, cx->parser.dport);
    } else {
        memset(dst, 0, sizeof(dst));
        CHECK(0 == str_tcp_endpoint(&outgoing->handle.tcp, peer, dst, sizeof(dst)));

        sprintf(cx->link_info, "%s -> %s", src, dst);
    }
}

void desc_upd_proxy_link(client_ctx *cx) {
    conn *incoming;
    char src[INET6_ADDRSTRLEN + 10];
    char dst[INET6_ADDRSTRLEN + 10];

    incoming = &cx->incoming;

    memset(src, 0, sizeof(src));
    CHECK(0 == str_tcp_endpoint(&incoming->handle.tcp, peer, src, sizeof(src)));

    memset(dst, 0, sizeof(dst));
    CHECK(0 == str_tcp_endpoint(&incoming->handle.tcp, sock, dst, sizeof(dst)));

    sprintf(cx->link_info, "%s -> %s", src, dst);
}

void desc_udp_endpoint_link(client_ctx *cx, server_endpoint *sp) {
    conn *incoming;
    char src[INET6_ADDRSTRLEN + 10];
    char dst[INET6_ADDRSTRLEN + 10];

    incoming = &cx->incoming;

    memset(src, 0, sizeof(src));
    CHECK(0 == str_tcp_endpoint(&incoming->handle.tcp, peer, src, sizeof(src)));

    if ( cx->parser.atyp == s5_atyp_host ) {
        /* as hostname */
        sprintf(sp->link_info, "%s -> %s:%d", src, cx->parser.daddr, cx->parser.dport);
    } else {
        memset(dst, 0, sizeof(dst));
        CHECK(0 == str_sockaddr(&sp->server.addr, dst, sizeof(dst)));
        sprintf(sp->link_info, "%s -> %s", src, dst);
    }
}

int str_sockaddr(const struct sockaddr *addr, char *buf, int buf_len) {
    const int min_buf_len = INET6_ADDRSTRLEN + 5 + 1 + 1; /* ipv6addr:port */
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;
    char ip[INET6_ADDRSTRLEN + 1];
    unsigned short port = 0;

    if ( buf_len < min_buf_len )
        return -1;

    switch (addr->sa_family) {
    case AF_INET:
        in = (const struct sockaddr_in *)addr;
        CHECK(0 == uv_ip4_name(in, ip, sizeof(ip)));
        port = htons_u(in->sin_port);

        break;
    case AF_INET6:
        in6 = (const struct sockaddr_in6 *)&addr;
        CHECK(0 == uv_ip6_name(in6, ip, sizeof(ip)));
        port = htons_u(in6->sin6_port);

        break;
    default:
        UNREACHABLE();
    }

    sprintf(buf, "%s:%d", ip, port);
    return 0;
}


int str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, char *buf, int buf_len) {
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len = sizeof(s);

    if ( ep == peer ) {
        CHECK(0 == uv_tcp_getpeername(tcp_handle,
                                       &s.addr,
                                       &addr_len));
    } else if ( ep == sock ) {
        CHECK(0 == uv_tcp_getsockname(tcp_handle,
                                       &s.addr,
                                       &addr_len));
    } else {
        UNREACHABLE();
    }

    return str_sockaddr(&s.addr, buf, buf_len);
}


int str_udp_endpoint(const uv_udp_t *udp_handle, char *buf, int buf_len) {
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len = sizeof(s);

    CHECK(0 == uv_udp_getsockname(udp_handle,
                                   &s.addr,
                                   &addr_len));

    return str_sockaddr(&s.addr, buf, buf_len);
}
