/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/22.
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
#include <stddef.h>

#ifndef UVSOCKS5_HDR_H
#define UVSOCKS5_HDR_H

#ifndef BASEDEFINE
#define BASEDEFINE

enum {
    STREAM_UP,      /* local -> remote */
    STREAM_DOWN     /* remote -> local */
};

enum {
    PASS,
    NEEDMORE,
    REJECT,
    TERMINATE
};

typedef struct ADDRESS{
    char host[64];      /* HostName or IpAddress */
    unsigned short port;
}ADDRESS;

typedef struct ADDRESS_PAIR{
    ADDRESS *local;
    ADDRESS *remote;
}ADDRESS_PAIR;

typedef struct MEM_RANGE{
    char *buf_base;
    size_t buf_len;
    char *data_base;
    size_t data_len;
}MEM_RANGE;

typedef void (*write_stream_out_callback)(void* param, int direct, int status, void *ctx);
typedef struct IOCTL_PORT{
    /* Interface for send data out */
    int (*write_stream_out)(
        MEM_RANGE *buf, int direct, void *stream_id,
        write_stream_out_callback callback, void *param);

    void (*stream_pause)(void *stream_id, int direct, int pause);
}IOCTL_PORT;

#endif

#endif
