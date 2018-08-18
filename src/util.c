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
#include "s5.h"
#include "internal.h"

int str_sockaddr(const struct sockaddr *addr, ADDRESS *addr_s) {
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;

    switch (addr->sa_family) {
    case AF_INET:
        in = (const struct sockaddr_in *)addr;
        CHECK(0 == uv_ip4_name(in, addr_s->host, sizeof(addr_s->host)));
        addr_s->port = htons_u(in->sin_port);

        break;
    case AF_INET6:
        in6 = (const struct sockaddr_in6 *)&addr;
        CHECK(0 == uv_ip6_name(in6, addr_s->host, sizeof(addr_s->host)));
        addr_s->port = htons_u(in6->sin6_port);

        break;
    default:
        UNREACHABLE();
    }

    return 0;
}

void cpy_sockaddr(const struct sockaddr *src, struct sockaddr *dst) {
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;

    switch (src->sa_family) {
    case AF_INET:
        in = (const struct sockaddr_in *)src;
        *(struct sockaddr_in *)dst = *in;
        break;

    case AF_INET6:
        in6 = (const struct sockaddr_in6 *)src;
        *(struct sockaddr_in6 *)dst = *in6;
        break;

    default:
        UNREACHABLE();
        break;
    }
}

int equal_sockaddr(const struct sockaddr *src, struct sockaddr *dst) {
    int ret = -1;
    const struct sockaddr_in6 *in6s;
    const struct sockaddr_in *ins;
    const struct sockaddr_in6 *in6d;
    const struct sockaddr_in *ind;

    if ( src->sa_family != dst->sa_family )
        BREAK_NOW;

    switch ( src->sa_family ) {
    case AF_INET:
        ins = (const struct sockaddr_in *)src;
        ind = (const struct sockaddr_in *)dst;
        if ( ins->sin_port != ind->sin_port )
            BREAK_NOW;
        if ( ins->sin_addr.s_addr != ind->sin_addr.s_addr )
            BREAK_NOW;
        break;

    case AF_INET6:
        in6s = (const struct sockaddr_in6 *)src;
        in6d = (const struct sockaddr_in6 *)dst;
        if ( in6s->sin6_port != in6d->sin6_port )
            BREAK_NOW;
        if ( 0 != memcmp(&in6s->sin6_addr, &in6d->sin6_addr, sizeof(in6s->sin6_addr)) )
            BREAK_NOW;
        break;

    default:
        UNREACHABLE();
        break;
    }

    ret = 0;
BREAK_LABEL:

    return ret;
}

void set_sockaddr_port(struct sockaddr *addr, unsigned short port) {
    struct sockaddr_in6 *in6;
    struct sockaddr_in *in;

    switch (addr->sa_family) {
    case AF_INET:
        in = (struct sockaddr_in *)addr;
        in->sin_port = port;
        break;

    case AF_INET6:
        in6 = (struct sockaddr_in6 *)addr;
        in6->sin6_port = port;
        break;

    default:
        UNREACHABLE();
        break;
    }
}

int str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, ADDRESS *addr_s) {
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

    return str_sockaddr(&s.addr, addr_s);
}


int str_udp_endpoint(const uv_udp_t *udp_handle, ADDRESS *addr_s) {
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len = sizeof(s);

    CHECK(0 == uv_udp_getsockname(udp_handle,
                                  &s.addr,
                                  &addr_len));

    return str_sockaddr(&s.addr, addr_s);
}


int s5_simple_check(const char *data, size_t data_len) {
    int ret;
    const char *p;
    int nmethod, i, method;

    if ( data_len < 3 ) {
        ret = s5_invalid_length;
        BREAK_NOW;
    }

    p = data;
    if ( *p != '\5' ) {
        ret = s5_invalid_version;
        BREAK_NOW;
    }

    nmethod = (int)*++p;
    if ( data_len < 2 + nmethod ) {
        ret = s5_invalid_length;
        BREAK_NOW;
    }

    ret = s5_invalid_method;
    for ( i = 0; i < nmethod; i++ ) {
        method = (int)*++p;
        if ( 0 == method ) {
            ret = 0;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

int s5_addr_copy(s5_ctx *ctx, struct sockaddr *addr, ADDRESS *addr_s) {
    struct sockaddr_in *in;
    struct sockaddr_in6 *in6;

    switch ( ctx->atyp ) {
    case s5_atyp_ipv4:
        in = (struct sockaddr_in *)addr;
        in->sin_family = AF_INET;
        in->sin_port = htons_u(ctx->dport);
        memcpy(&in->sin_addr, ctx->daddr, sizeof(in->sin_addr));

        CHECK(0 == uv_ip4_name(in, addr_s->host, sizeof(addr_s->host)));
        addr_s->port = ctx->dport;
        break;
    case s5_atyp_ipv6:
        in6 = (struct sockaddr_in6 *)addr;
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons_u(ctx->dport);
        memcpy(&in6->sin6_addr, ctx->daddr, sizeof(in6->sin6_addr));

        CHECK(0 == uv_ip6_name(in6, addr_s->host, sizeof(addr_s->host)));
        addr_s->port = ctx->dport;
        break;
    case s5_atyp_host:
        snprintf(
            addr_s->host,
            sizeof(addr_s->host),
            "%.*s",
            (int)strlen((char*)ctx->daddr),
            ctx->daddr);

        addr_s->port = ctx->dport;
        break;
    default:
        UNREACHABLE();
    }

    return 0;
}
