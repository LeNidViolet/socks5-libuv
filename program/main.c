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
#include <stdio.h>
#include <string.h>
#include "uvsocks5/uvsocks5.h"

typedef struct {
    unsigned int index;
    ADDRESS local;
    ADDRESS remote;
} STREAM_SESSION;

typedef struct {
    unsigned int index;
    ADDRESS local;
    ADDRESS remote;
} DGRAM_SESSION;

void on_msg(int level, const char *msg) {
    printf("%d %s\n", level, msg);
}

void on_bind(const char *host, unsigned short port) {
    printf("LISTENING ON %s:%d\n", host, port);
}

void on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx) {
    STREAM_SESSION *ss;

    ss = (STREAM_SESSION*)ctx;

    ss->local = *addr->local;
    ss->remote = *addr->remote;

    printf("[%d] CONNECTION MADE %s:%d -> %s:%d\n",
        ss->index,
        addr->local->host, addr->local->port,
        addr->remote->host, addr->remote->port);
}

void on_new_stream(ADDRESS *addr, void **ctx, void *stream_id) {
    static unsigned int index = 0;
    STREAM_SESSION *ss;

    (void)addr;
    (void)stream_id;

    ss = malloc(sizeof(*ss));
    memset(ss, 0, sizeof(*ss));
    ss->index = index++;

    *ctx = ss;
}

void on_stream_teardown(void *ctx) {
    STREAM_SESSION *ss;

    ss = (STREAM_SESSION*)ctx;

    printf("CONNECTION LOST %s:%d -> %s:%d\n",
           ss->local.host, ss->local.port,
           ss->remote.host, ss->remote.port);
    free(ss);
}

void on_new_dgram(ADDRESS_PAIR *addr, void **ctx) {
    static unsigned int index = 0;
    DGRAM_SESSION *ds;

    ds = malloc(sizeof(*ds));
    memset(ds, 0, sizeof(*ds));
    ds->index = index++;

    ds->local = *addr->local;
    ds->remote = *addr->remote;

    printf("[%d] DGRAM MADE %s:%d -> %s:%d\n",
           ds->index,
           addr->local->host, addr->local->port,
           addr->remote->host, addr->remote->port);

    *ctx = ds;
}

void on_dgram_teardown(void *ctx) {
    DGRAM_SESSION *ds;

    ds = (DGRAM_SESSION*)ctx;

    printf("DGRAM LOST %s:%d -> %s:%d\n",
           ds->local.host, ds->local.port,
           ds->remote.host, ds->remote.port);
    free(ds);
}

void on_plain_stream(MEM_RANGE *buf, int direct, void *ctx) {
    STREAM_SESSION *ss;
    char *desc = direct == STREAM_UP ? "==>" : "<==";

    ss = (STREAM_SESSION*)ctx;

    (void)ss;
    (void)desc;
    (void)buf;
}

void on_plain_dgram(MEM_RANGE *buf, int direct, void *ctx) {
    DGRAM_SESSION *ds;
    char *desc = direct == STREAM_UP ? "==>" : "<==";

    ds = (DGRAM_SESSION*)ctx;
    (void)ds;
    (void)desc;
    (void)buf;
}

int main(int argc, char **argv) {
    UVSOCKS5_CTX ctx = {0};

    ctx.callbacks.on_msg = on_msg;
    ctx.callbacks.on_bind = on_bind;
    ctx.callbacks.on_stream_connection_made = on_stream_connection_made;

    ctx.callbacks.on_new_stream = on_new_stream;
    ctx.callbacks.on_stream_teardown = on_stream_teardown;

    ctx.callbacks.on_new_dgram = on_new_dgram;
    ctx.callbacks.on_dgram_teardown = on_dgram_teardown;

    ctx.callbacks.on_plain_stream = on_plain_stream;
    ctx.callbacks.on_plain_dgram = on_plain_dgram;

    uvsocks5_server_launch(&ctx);

    return 0;
}
