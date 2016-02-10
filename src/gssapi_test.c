/* gssapi_test.c
 *
 * Matt Rogers <mrogers@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <gssapi/gssapi.h>

#define bool int
#define true  1
#define false 0
#define MAX_BUF_SIZE 1024
#define SOCK_PATH "/tmp/gss-test"

bool gdebug = false;
const char *gmode = NULL;
const char *progname = NULL;
OM_uint32 gignore;
const char *const short_opts = "dm:n:S:";

static struct option long_opts[] = {
    { "debug", no_argument, NULL, 'd' } ,
    { "mode", required_argument, NULL, 'm' },
    { "name", required_argument, NULL, 'n' },
    { "socket", required_argument, NULL, 'S' },
    { 0, 0, 0, 0 }
};

struct config {
    char *target_name;
    const char *sock_name;
    int sock;
};

static inline bool strequal(const char *s1, const char *s2)
{
    return strcmp(s1, s2) == 0;
}

static void usage(void)
{
    fprintf(stderr, "usage: %s -m server|client [-n target_name] [-S socket_path] [-d]\n", progname);
    exit(1);
}

static void print_error(const char *reason)
{
    fprintf(stderr, "ERROR - %s\n", reason);
}

static void print_gss_error(const char *reason, OM_uint32 maj, OM_uint32 min)
{
    gss_buffer_desc errbuf;
    OM_uint32 msgctx, lmaj, lmin;
    lmaj = gss_display_status(&lmin, maj, GSS_C_GSS_CODE,
                                 GSS_C_NO_OID, &msgctx, &errbuf);
    if (lmaj != GSS_S_COMPLETE) {
        fprintf(stderr, "unknown GSS ERROR - %s [%x/%x]\n", reason, maj, min);
        return;
    }
    fprintf(stderr, "GSS ERROR - %s [%x/%x] - %s\n", reason, maj, min,
                                                     (char *) errbuf.value);
}

static int setup_name(char *target_name, gss_name_t *name)
{
    int r = 0;
    OM_uint32 maj, minor;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;

    if (target_name != NULL) {
        buf.length = strlen(target_name);
        buf.value = target_name;
        maj = gss_import_name(&minor, &buf, GSS_C_NT_HOSTBASED_SERVICE, name);
        if (maj != GSS_S_COMPLETE) {
            print_gss_error("gss_import_name", maj, minor);
            r = -1;
        }
    }
    return r;
}

static void debug_buf(const char *name, char *buf, size_t size)
{
	int i;
    if (gdebug) {
        fprintf(stdout, "%s buf len %lu:\n", name, size);
        for (i = 0; i < (int)size; i++) {
            fprintf(stdout, "%.2x", buf[i] & 0xff);
        }
        fprintf(stdout, "\n");
    }
}

static int recv_msg(int s, char *buf, size_t buf_len)
{
    int t = recv(s, (void *)buf, buf_len, 0);
    if (t == -1) {
        perror("recv");
        return -1;
    }
    return t;
}

static int send_msg(int s, char *buf, size_t buf_len)
{
    if (send(s, buf, buf_len, 0) == -1) {
        perror("send");
        return -1;
    }
    return 0;
}

static int negotiate_server(struct config *conf, gss_ctx_id_t *ctx,
                                          gss_buffer_desc *in_token)
{
    OM_uint32 maj, minor;
    gss_cred_id_t cred = NULL;
    gss_name_t name = NULL, srcname = NULL;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    struct sockaddr_un remote;
    int rmsg, remote_len, s2 = -1, ret = 0;
    char *recv_buf;

    recv_buf = (char *)calloc(MAX_BUF_SIZE, sizeof(char));
    if (recv_buf == NULL) {
        print_error("calloc");
        return -1;
    }

    if (setup_name(conf->target_name, &name) == -1) {
        ret = -1;
        goto end;
    }

    if (name != GSS_C_NO_NAME) {
        maj = gss_acquire_cred(&minor, name,
                               GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                               GSS_C_ACCEPT, &cred, NULL, NULL);
        if (maj != GSS_S_COMPLETE) {
            print_gss_error("gss_acquire_cred", maj, minor);
            ret = -1;
            goto end;
        }
    }

    fprintf(stdout, "Connecting.. \n");
    s2 = accept(conf->sock, (struct sockaddr *)&remote,
                            (socklen_t *)&remote_len);
    if (s2 == -1) {
        perror("accept");
        ret = -1;
        goto end;
    }

    fprintf(stdout, "Connected.\n");
    do {
        rmsg = recv_msg(s2, recv_buf, MAX_BUF_SIZE);
        if (rmsg == -1 || rmsg > MAX_BUF_SIZE) {
            print_error("server recv_msg");
            ret = -1;
            goto end;
        }

        in_token->value = recv_buf;
        in_token->length = rmsg;

        debug_buf("received", (char *)in_token->value, in_token->length);

        maj = gss_accept_sec_context(&minor, ctx, cred, in_token,
                                     GSS_C_NO_CHANNEL_BINDINGS, &srcname,
                                     NULL, &output, NULL, NULL, NULL);

        if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
            print_gss_error("gss_accept_sec_context", maj, minor);
            ret = -1;
            goto end;
        }

        if (output.length > MAX_BUF_SIZE) {
            print_error("no space for output length");
            ret = -1;
            goto end;
        }

        if (output.length > 0) {
            debug_buf("send", (char *)output.value, output.length);
            rmsg = send_msg(s2, (char *)output.value, output.length);
            (void)gss_release_buffer(&gignore, &output);
            if (rmsg == -1) {
                print_error("server send_msg");
                ret = -1;
                goto end;
            }
        }
    } while (maj == GSS_S_CONTINUE_NEEDED);

end:
    free(recv_buf);
    if (s2 != -1)
        close(s2);
    return ret;
}

static int negotiate_client(struct config *conf, gss_ctx_id_t *ctx,
                     gss_buffer_desc *in_token)
{
    OM_uint32 maj, minor;
    gss_cred_id_t cred = NULL;
    gss_name_t name = NULL;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_cred_usage_t usage;
    int rmsg, ret = 0;
    char *recv_buf = NULL;

    recv_buf = (char *)calloc(MAX_BUF_SIZE, sizeof(char));
    if (recv_buf == NULL) {
        print_error("calloc");
        return -1;
    }

    if (setup_name(conf->target_name, &name) == -1) {
        ret = -1;
        goto end;
    }
    usage = GSS_C_MUTUAL_FLAG |
            GSS_C_REPLAY_FLAG |
            GSS_C_SEQUENCE_FLAG |
            GSS_C_CONF_FLAG |
            GSS_C_INTEG_FLAG;

    do {
        maj = gss_init_sec_context(&minor, cred, ctx, name,
                                   GSS_C_NO_OID, usage, 0,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   in_token, NULL, &output,
                                   NULL, NULL);

        if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
            print_gss_error("gss_init_sec_context", maj, minor);
            ret = -1;
            goto end;
        }
        if (output.length > MAX_BUF_SIZE) {
            print_error("not enough space for output token");
            ret = -1;
            goto end;
        }
        if (output.length > 0) {
            debug_buf("send", (char *)output.value, output.length);
            rmsg = send_msg(conf->sock, (char *)output.value, output.length);
            (void)gss_release_buffer(&gignore, &output);
            if (rmsg < 0) {
                print_error("client send_msg");
                ret = -1;
                goto end;
            }
        }
        if (maj == GSS_S_CONTINUE_NEEDED) {
            rmsg = recv_msg(conf->sock, recv_buf, MAX_BUF_SIZE);
            if (rmsg == -1) {
                print_error("client read_msg");
                ret = -1;
                goto end;
            }
            debug_buf("received", recv_buf, rmsg);
            in_token->value = recv_buf;
            in_token->length = rmsg;
        }
    } while(maj == GSS_S_CONTINUE_NEEDED);

end:
    free(recv_buf);
    return ret;

}

static int do_client(struct config *conf)
{

    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx = NULL;
    struct sockaddr_un sa;
    int len, r = 0;
    struct stat st;

    if (stat(conf->sock_name, &st) != 0) {
        fprintf(stderr, "no socket %s\n", conf->sock_name);
        return 1;
    }
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, conf->sock_name);
    len = strlen(sa.sun_path) + sizeof(sa.sun_family);
    if (connect(conf->sock, (struct sockaddr *)&sa, len) == -1) {
        perror("connect");
        r = 1;
        goto end;
    }

    if (negotiate_client(conf, &ctx, &token) == -1) {
        r = 1;
    }

end:
    fprintf(stdout, "Client negotiation %s\n", r == 0 ? "OK" : "FAILED");
    close(conf->sock);
    return r;
}

static int do_server(struct config *conf)
{
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx = NULL;
    struct sockaddr_un sa;
    int len, r = 0;
    struct stat st;

    if (stat(conf->sock_name, &st) == 0) {
        unlink(conf->sock_name);
    }
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, conf->sock_name);
    len = strlen(sa.sun_path) + sizeof(sa.sun_family);
    if (bind(conf->sock, (struct sockaddr *)&sa, len) == -1) {
        perror("bind");
        r = 1;
        goto end;
    }
    if (listen(conf->sock, 5) == -1) {
        perror("listen");
        r = 1;
        goto end;
    }

    if (negotiate_server(conf, &ctx, &token) == -1) {
        r = 1;
    }

end:
    fprintf(stdout, "Server negotiation %s\n", r == 0 ? "OK" : "FAILED");
    close(conf->sock);
    unlink(conf->sock_name);
    return r;
}

int main(int argc, char **argv)
{
    int c, ret;
    struct config conf = { NULL, NULL, 0 };

    progname = argv[0];
    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != EOF) {
        switch(c) {
        case 'd':
            gdebug = true;
            break;
        case 'm':
            if (strequal(optarg, "server") || strequal(optarg, "client"))
                gmode = optarg;
            else
                usage();
            break;
        case 'n':
            conf.target_name = optarg;
            break;
        case 'S':
            conf.sock_name = optarg;
            break;
        case '?':
        default:
            usage();
        case -1:
            break;
        }
    }

    if (gmode == NULL) {
        usage();
    }

    if ((conf.sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return 1;
    }

    if (conf.sock_name == NULL) {
        conf.sock_name = SOCK_PATH;
    }

    if (strequal(gmode, "server")) {
        ret = do_server(&conf);
    } else {
        ret = do_client(&conf);
    }
    exit(ret);
}
