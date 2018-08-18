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
#include <stdio.h>
#include <zconf.h>
#include "uvsocks5/uvsocks5.h"
#include "internal.h"

void notify_msg_out(int level, const char *format, ...) {
    va_list ap;
    char msg[1024];

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_msg);

    va_start(ap, format);

    vsnprintf(msg, sizeof(msg), format, ap);
    uvsocks5_ctx.callbacks.on_msg(level, msg);

    va_end(ap);

BREAK_LABEL:

    return;
}

void notify_bind(const char *host, unsigned short port) {

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_bind);

    uvsocks5_ctx.callbacks.on_bind(host, port);

BREAK_LABEL:

    return;
}

void notify_connection_made(PROXY_NODE *pn) {
    ADDRESS_PAIR pair;

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_stream_connection_made);

    pair.local = &pn->incoming.peer;
    pair.remote = &pn->outgoing.peer;

    uvsocks5_ctx.callbacks.on_stream_connection_made(&pair, pn->ctx);

BREAK_LABEL:

    return;
}


void handle_new_stream(CONN *conn) {
    void *ctx = NULL;

    CHECK(0 == str_tcp_endpoint(&conn->handle.tcp, peer, &conn->peer));

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_new_stream);

    uvsocks5_ctx.callbacks.on_new_stream(&conn->peer, &ctx);
    conn->pn->ctx = ctx;

BREAK_LABEL:

    return;
}

void handle_stream_teardown(PROXY_NODE *pn) {

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_stream_teardown);

    uvsocks5_ctx.callbacks.on_stream_teardown(pn->ctx);

BREAK_LABEL:

    return;
}

void handle_new_dgram(ADDRESS *local, ADDRESS *remote, void **ctx) {
    ADDRESS_PAIR pair;

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_new_dgram);

    pair.local = local;
    pair.remote = remote;

    uvsocks5_ctx.callbacks.on_new_dgram(&pair, ctx);

BREAK_LABEL:

    return;
}

void handle_dgram_teardown(void *ctx) {

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_dgram_teardown);

    uvsocks5_ctx.callbacks.on_dgram_teardown(ctx);

BREAK_LABEL:

    return;
}

void handle_plain_stream(CONN *conn) {
    int direct = conn == &conn->pn->incoming ? STREAM_UP : STREAM_DOWN;

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_plain_stream);

    uvsocks5_ctx.callbacks.on_plain_stream(
        &conn->us_buf,
        direct,
        conn->pn->ctx);

BREAK_LABEL:

    return;
}
