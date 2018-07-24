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

#include "../src/defs.h"
#include <stdlib.h>

#if HAVE_UNISTD_H
#include <unistd.h>  /* getopt */
#endif

#define DEFAULT_BIND_HOST     "127.0.0.1"
#define DEFAULT_BIND_PORT     1080
#define DEFAULT_IDLE_TIMEOUT  (60 * 1000)

static void parse_opts(server_config *cf, int argc, char **argv);
static void usage(void);

static const char *progname = __FILE__;  /* Reset in main(). */

int main(int argc, char **argv) {
    server_config config;
    int err;

    progname = argv[0];
    memset(&config, 0, sizeof(config));
    config.bind_host = DEFAULT_BIND_HOST;
    config.bind_port = DEFAULT_BIND_PORT;
    config.idle_timeout = DEFAULT_IDLE_TIMEOUT;
    config.auth_none = 1;
    config.username = NULL;
    config.password = NULL;
    parse_opts(&config, argc, argv);

    err = server_run(&config, uv_default_loop());
    if (err) {
        exit(1);
    }

    return 0;
}

const char *_getprogname(void) {
    return progname;
}

static void parse_opts(server_config *cf, int argc, char **argv) {
    int opt;
    static char username[256];
    static char password[256];

    while (-1 != (opt = getopt(argc, argv, "b:hp:u:w:"))) {
        switch (opt) {
        case 'b':
            cf->bind_host = optarg;
            break;

        case 'p':
            if (1 != sscanf(optarg, "%hu", &cf->bind_port)) {
                pr_err("bad port number: %s", optarg);
                usage();
            }
            break;

        case 'u':
            memset(username, 0, sizeof(username));
            if ( strlen(optarg) >= sizeof(username) ) {
                pr_err("user name too long (max 255) %s", optarg);
                usage();
            }
            else
            {
                sprintf(username, "%s", optarg);
                cf->username = username;
            }
            break;

        case 'w':
            memset(password, 0, sizeof(password));
            if ( strlen(optarg) >= sizeof(password) ) {
                pr_err("password too long (max 255) %s", optarg);
                usage();
            }
            else
            {
                sprintf(password, "%s", optarg);
                cf->password = password;
            }
            break;

        default:
            usage();
        }
    }

    if ( cf->username && cf->password )
        cf->auth_none = 0;
}

static void usage(void) {
    printf("Usage:\n"
           "\n"
           "  %s [-b <address>] [-h] [-p <port>] [-u <username>] [-w <password>]\n"
           "\n"
           "Options:\n"
           "\n"
           "  -b <hostname|address>  Bind to this address or hostname.\n"
           "                         Default: \"127.0.0.1\"\n"
           "  -h                     Show this help message.\n"
           "  -p <port>              Bind to this port number.  Default: 1080\n"
           "  -u <username>          User name to connect to this proxy.\n"
           "  -w <password>          Password to connect to this proxy.\n"
           "\n"
           "  If neither a username nor a password is provided, the proxy does not need to be authenticated."
           "",
           progname);
    exit(1);
}
