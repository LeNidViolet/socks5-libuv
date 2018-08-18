/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/6.
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
#ifndef SHADOWSOCKS_NETIO_LIST_H
#define SHADOWSOCKS_NETIO_LIST_H

#ifndef _WIN32
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;
#endif

void InitializeListHead(PLIST_ENTRY ListHead);

int IsListEmpty(const LIST_ENTRY *ListHead);

int RemoveEntryList(PLIST_ENTRY Entry);

void InsertHeadList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry
);

void InsertTailList(
    PLIST_ENTRY ListHead,
    PLIST_ENTRY Entry
);

PLIST_ENTRY RemoveHeadList(PLIST_ENTRY ListHead);

PLIST_ENTRY RemoveTailList(PLIST_ENTRY ListHead);

#endif //SHADOWSOCKS_NETIO_LIST_H
