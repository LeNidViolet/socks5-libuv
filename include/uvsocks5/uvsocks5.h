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
#ifndef UVSOCKS5_UVSOCKS5_H
#define UVSOCKS5_UVSOCKS5_H

#include <stddef.h>
#include <netinet/in.h>
#include "hdr.h"

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct UVSOCKS5_BASE_CONFIG{
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idel_timeout;
}UVSOCKS5_BASE_CONFIG;

typedef struct UVSOCKS5_CALLBACKS{
    /* Event Notify, Can be NULL */
    void (*on_msg)(int level, const char *msg);
    void (*on_bind)(const char *host, unsigned short port);
    void (*on_stream_connection_made)(ADDRESS_PAIR *addr, void *ctx);

    /* A new request coming,
     * set data to a context associate with this session,
     * */
    void (*on_new_stream)(ADDRESS *addr, void **ctx, void *stream_id);
    void (*on_stream_teardown)(void *ctx);

    /* A new udp dgram request
     * set data to a context associate with it
     * */
    void (*on_new_dgram)(ADDRESS_PAIR *addr, void **ctx);
    void (*on_dgram_teardown)(void *ctx);

    int (*on_plain_stream)(MEM_RANGE *buf, int direct, void *ctx);
    void (*on_plain_dgram)(MEM_RANGE *buf, int direct, void *ctx);

}UVSOCKS5_CALLBACKS;

typedef struct UVSOCKS5_CTX{
    UVSOCKS5_BASE_CONFIG config;
    UVSOCKS5_CALLBACKS callbacks;
}UVSOCKS5_CTX;

int uvsocks5_server_launch(UVSOCKS5_CTX *ctx);
void uvsocks5_server_port(IOCTL_PORT *port);
#endif //UVSOCKS5_UVSOCKS5_H
