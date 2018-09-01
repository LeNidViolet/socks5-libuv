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

static void uvsocks5_write_stream_out_done(uv_write_t *req, int status);

typedef struct {
    write_stream_out_callback callback;
    void *param;
}SND_CTX;

void uvsocks5_on_msg(int level, const char *format, ...) {
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

void uvsocks5_on_bind(const char *host, unsigned short port) {

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_bind);

    uvsocks5_ctx.callbacks.on_bind(host, port);

BREAK_LABEL:

    return;
}

void uvsocks5_on_connection_made(PROXY_NODE *pn) {
    ADDRESS_PAIR pair;

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_stream_connection_made);

    pair.local = &pn->incoming.peer;
    pair.remote = &pn->outgoing.peer;

    uvsocks5_ctx.callbacks.on_stream_connection_made(&pair, pn->ctx);

BREAK_LABEL:

    return;
}


void uvsocks5_on_new_stream(CONN *conn) {
    void *ctx = NULL;

    CHECK(0 == str_tcp_endpoint(&conn->handle.tcp, peer, &conn->peer));

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_new_stream);

    uvsocks5_ctx.callbacks.on_new_stream(&conn->peer, &ctx, conn->pn);
    conn->pn->ctx = ctx;

BREAK_LABEL:

    return;
}

void uvsocks5_on_stream_teardown(PROXY_NODE *pn) {

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_stream_teardown);

    uvsocks5_ctx.callbacks.on_stream_teardown(pn->ctx);

BREAK_LABEL:

    return;
}

void uvsocks5_on_new_dgram(ADDRESS *local, ADDRESS *remote, void **ctx) {
    ADDRESS_PAIR pair;

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_new_dgram);

    pair.local = local;
    pair.remote = remote;

    uvsocks5_ctx.callbacks.on_new_dgram(&pair, ctx);

BREAK_LABEL:

    return;
}

void uvsocks5_on_dgram_teardown(void *ctx) {

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_dgram_teardown);

    uvsocks5_ctx.callbacks.on_dgram_teardown(ctx);

BREAK_LABEL:

    return;
}

int uvsocks5_on_plain_stream(CONN *conn) {
    int ret = PASS;
    MEM_RANGE mr;
    int direct = conn == &conn->pn->incoming ? STREAM_UP : STREAM_DOWN;

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_plain_stream);

    mr.buf_base = conn->t.raw;
    mr.buf_len = sizeof(conn->t.raw);
    mr.data_base = conn->us_buf.buf_base;
    mr.data_len = (size_t)conn->result;

    ret = uvsocks5_ctx.callbacks.on_plain_stream(
        &mr,
        direct,
        conn->pn->ctx);

BREAK_LABEL:

    return ret;
}

void uvsocks5_on_plain_dgram(UVSOCKS5_BUF *buf, int direct, void *ctx) {
    MEM_RANGE mr;

    BREAK_ON_NULL(uvsocks5_ctx.callbacks.on_plain_dgram);

    mr.buf_base = buf->buf_base;
    mr.buf_len = buf->buf_len;
    mr.data_base = buf->buf_base;
    mr.data_len = buf->buf_len;

    uvsocks5_ctx.callbacks.on_plain_dgram(&mr, direct, ctx);

BREAK_LABEL:

    return ;
}

int uvsocks5_write_stream_out(
    MEM_RANGE *buf, int direct, void *stream_id,
    write_stream_out_callback callback, void *param) {
    int ret = -1;
    PROXY_NODE *pn;
    CONN *conn;
    uv_buf_t buf_t;
    SND_CTX *snd_ctx;

    BREAK_ON_NULL(buf);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);
    BREAK_ON_NULL(stream_id);

    pn = (PROXY_NODE*)stream_id;
    conn = STREAM_UP == direct ? &pn->outgoing : &pn->incoming;

    ASSERT(conn->wrstate == c_stop || conn->wrstate == c_done);
    conn->wrstate = c_busy;

    buf_t = uv_buf_init(buf->data_base, (unsigned int)buf->data_len);

    snd_ctx = malloc(sizeof(*snd_ctx));
    CHECK(snd_ctx);
    snd_ctx->callback = callback;
    snd_ctx->param = param;
    uv_req_set_data((uv_req_t*)&conn->write_req, snd_ctx);
    if ( 0 != uv_write(&conn->write_req,
                       &conn->handle.stream,
                       &buf_t,
                       1,
                       uvsocks5_write_stream_out_done) ) {
        free(snd_ctx);
        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->pn->outstanding++;
    conn_timer_reset(conn);

    ret = 0;

BREAK_LABEL:

    return ret;
}

static void uvsocks5_write_stream_out_done(uv_write_t *req, int status) {
    CONN *conn;
    SND_CTX *snd_ctx;
    int direct;

    conn = CONTAINER_OF(req, CONN, write_req);
    conn->pn->outstanding--;
    ASSERT(conn->wrstate == c_busy);
    conn->wrstate = c_stop;

    direct = conn == &conn->pn->incoming ? STREAM_DOWN : STREAM_UP;

    snd_ctx = uv_req_get_data((uv_req_t*)req);
    if ( snd_ctx->callback )
        snd_ctx->callback(snd_ctx->param, direct, status, conn->pn->ctx);

    free(snd_ctx);
}

void uvsocks5_stream_pause(void *stream_id, int direct, int pause) {
    PROXY_NODE *pn;
    CONN *conn;

    BREAK_ON_NULL(stream_id);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);

    pn = (PROXY_NODE*)stream_id;
    conn = STREAM_UP == direct ? &pn->outgoing : &pn->incoming;
    if ( pause ) {
        if ( c_busy == conn->rdstate )
            uv_read_stop(&conn->handle.stream);
        if ( c_stop != conn->rdstate )
            conn->rdstate = c_stop;
    } else {
        if ( c_busy != conn->rdstate ) {
            if ( c_stop != conn->rdstate )
                conn->rdstate = c_stop;
            conn_read(conn);
        }
    }

BREAK_LABEL:

    return;
}
