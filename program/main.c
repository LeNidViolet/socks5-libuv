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
#include "uvsocks5/uvsocks5.h"

void on_msg(int level, const char *msg) {
    printf("%d %s\n", level, msg);
}

void on_bind(const char *host, unsigned short port) {
    printf("LISTENING ON %s:%d\n", host, port);
}

void on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx) {
    printf("CONNECTION MADE %s:%d -> %s:%d\n",
        addr->local->host, addr->local->port,
        addr->remote->host, addr->remote->port);
}

int main(int argc, char **argv) {
    UVSOCKS5_CTX ctx = {0};

    ctx.callbacks.on_msg = on_msg;
    ctx.callbacks.on_bind = on_bind;
    ctx.callbacks.on_stream_connection_made = on_stream_connection_made;

    ssnetio_server_launch(&ctx);


    return 0;
}
