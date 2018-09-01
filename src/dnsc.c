/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/7.
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
#include "dnsc.h"
#include "internal.h"

static LIST_ENTRY dnsc_list;

static int dnsc_outstanding = 0;

static void dnsc_free(DNSC *dnsc);

/* TODO: ADD DNS TIMEOUT */

int dnsc_init(void) {
    InitializeListHead(&dnsc_list);

    return 0;
}

DNSC *dnsc_find(char *host) {
    DNSC *ret = NULL, *dnsc;
    LIST_ENTRY *next;

    BREAK_ON_NULL(host);

    for ( next = dnsc_list.Blink; next != &dnsc_list; next = next->Blink ) {
        dnsc = CONTAINER_OF(next, DNSC, list);

        if ( 0 == strcasecmp(host, dnsc->host) ) {
            ret = dnsc;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

DNSC *dnsc_add(char *host, struct sockaddr *addr) {
    DNSC *ret = NULL;

    BREAK_ON_NULL(host);

    ret = dnsc_find(host);
    if ( ret ) {
        if ( addr ) {
            cpy_sockaddr(addr, &ret->t.addr);
        }
    } else {
        ENSURE((ret = malloc(sizeof(*ret))) != NULL);
        memset(ret, 0, sizeof(*ret));

        snprintf(ret->host, sizeof(ret->host), "%s", host);
        if ( addr ) {
            cpy_sockaddr(addr, &ret->t.addr);
        }

        InsertTailList(&dnsc_list, &ret->list);

        dnsc_outstanding++;
    }

BREAK_LABEL:

    return ret;
}

void dnsc_remove(DNSC *dnsc) {
    if ( dnsc ) {
        RemoveEntryList(&dnsc->list);

        dnsc_free(dnsc);
    }
}


void dnsc_clear(void) {
    DNSC *dnsc;
    LIST_ENTRY *list;

    while ( !IsListEmpty(&dnsc_list) ) {
        list = RemoveHeadList(&dnsc_list);
        dnsc = CONTAINER_OF(list, DNSC, list);

        dnsc_free(dnsc);
    }
}

static void dnsc_free(DNSC *dnsc) {
    if ( DEBUG_CHECKS )
        memset(dnsc, -1, sizeof(*dnsc));

    free(dnsc);

    dnsc_outstanding--;
}
