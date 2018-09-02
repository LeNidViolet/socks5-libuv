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

#define DEFAULT_S5_BIND_HOST            ("0.0.0.0")
#define DEFAULT_S5_BIND_PORT            (10890)
#define DEFAULT_S5_IDEL_TIMEOUT         (60 * 1000)

#define MAX_S5_HDR_LEN                  (255 + 6)
#define MAX_S5_TCP_PAYLOAD_LEN          (2048)
#define MAX_S5_UDP_PAYLOAD_LEN          (512)

#define S5_IPV4_UDP_SEND_HDR_LEN        10
#define S5_IPV6_UDP_SEND_HDR_LEN        22

#define MAX_S5_TCP_FRAME_LEN       (MAX_S5_TCP_PAYLOAD_LEN)
#define MAX_S5_UDP_FRAME_LEN       (MAX_S5_UDP_PAYLOAD_LEN + MAX_S5_HDR_LEN)

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
