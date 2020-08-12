#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include "cmdcat.h"
#include "utils.h"

int avail_socket = 0;

static int __sendmsg(const char* buf, size_t len) //{
{
    printf("new message: %s\n", buf);
    DEBUG();
    assert(avail_socket > 0);
    int fd = avail_socket;

    char sizebuf[2];
    *(uint16_t*)sizebuf = htons(len);
    int slen = send(fd, sizebuf, sizeof(sizebuf), 0);
    if(slen != 2) {
        close(fd);
        avail_socket = 0;
        return 0;
    }
    slen = send(fd, buf, len, 0);

    if(slen != len) {
        close(fd);
        avail_socket = 0;
        return 0;
    }
    return 1;
} //}
static int __sendmsg_inet(const char* buf, size_t len, uint16_t port, uint32_t addr) //{
{
START:
    DEBUG();
    int redoable = 0;
    if(avail_socket > 0) {
        redoable = 1;
    } else {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(fd < 0) return 0;

        struct sockaddr_in s_addr;
        s_addr.sin_family = AF_INET;
        s_addr.sin_addr.s_addr = addr;
        s_addr.sin_port = port;
        if(connect(fd, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0) {
            close(fd);
            return 0;
        }

        if(fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
            return 0;
        avail_socket = fd;
    }

    int r = __sendmsg(buf, len);
    if(!r && redoable) goto START;
    return r;
} //}
static int __sendmsg_unix(const char* buf, size_t len, const char* path) //{
{
START:
    DEBUG();
    int redoable = 0;
    if(avail_socket > 0) {
        redoable = 1;
    } else {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if(fd < 0) return 0;

        struct sockaddr_un s_addr;
        s_addr.sun_family = AF_UNIX;
        memcpy(s_addr.sun_path, path, sizeof(s_addr.sun_path));

        if(connect(fd, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0) {
            close(fd);
            return 0;
        }

        if(fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
            return 0;
        avail_socket = fd;
    }

    int r = __sendmsg(buf, len);
    if(!r && redoable) goto START;
    return r;
} //}
static void clean_socket() __attribute__((destructor));
static void clean_socket() //{
{
    if(avail_socket > 0) {
        close(avail_socket);
        avail_socket = 0;
    }
} //}

#define MINIMUM_STR_SIZE 2047
#define SIZE__MAX(a, b) (a < b ? b : a)
static char* strnew(const char* str) //{
{
    char* result = (char*)malloc(SIZE__MAX(strlen(str), MINIMUM_STR_SIZE) + 1);
    memcpy(result, str, strlen(str));
    result[strlen(str)] = 0;
    return result;
} //}
static char* stradd(char* d1, const char* d2) //{
{
    size_t all_len = strlen(d1) + strlen(d2);
    size_t tlen = 0;
    for(int i=11;i<sizeof(size_t) * 8;i++) {
        size_t k = (1 << i);
        if(k > all_len) {
            tlen = k;
            break;
        }
    }
    assert(tlen > 0);
    char* result = (char*)realloc(d1, tlen);
    memcpy(result + strlen(result), d2, strlen(d2));
    result[all_len] = 0;
    return result;
} //}

static char* double_quote_string(const char* str) //{
{
    size_t len = strlen(str);
    char* result = (char*)malloc(len * 2 + 2);
    size_t pos = 0;
    result[pos++] = '"';
    for(size_t i=0;i<len;i++) {
        char c = str[i];
        switch(c) {
            case '\\':
                result[pos++] = '\\';
                result[pos++] = '\\';
                break;
            case '"':
                result[pos++] = '\\';
                result[pos++] = '"';
                break;
            default:
                result[pos++] = c;
                break;
        }
    }
    result[pos++] = '"';
    result[pos++] = 0;
    return result;
} //}
static char* stradd_quotelast(char* d1, const char* d2) //{
{
    char* q = double_quote_string(d2);
    char* r = stradd(d1, q);
    free(q);
    return r;
} //}

static const char* __itoa(int i) //{
{
    static char buf[32];
    sprintf(buf, "%i", i);
    return buf;
} //}

static int send_generic(const char* fname, pid_t ppid, pid_t pid, 
                        const char* cmd,   char* const argv[], char* const env[]) //{
{
    DEBUG();
    char* msg = strnew(
        "{\n"
        "    \"function\": \""); msg = stradd(msg, fname); msg = stradd(msg, "\",\n");

    if(ppid >= 0) {
        msg = stradd(msg, "    \"ppid\": "); 
        msg = stradd(msg, __itoa(ppid)); 
        msg = stradd(msg, ",\n");
    }
    msg = stradd(msg, "    \"pid\": ");  msg = stradd(msg, __itoa(pid));  msg = stradd(msg, ",\n");

    if(cmd != NULL) {
        msg = stradd(msg, "    \"cmd\": \"");
        msg = stradd(msg, cmd);
        msg = stradd(msg, "\",\n");
    }
    if(argv != NULL) {
        msg = stradd(msg, "    \"args\": {\n");
        for(int i=0;argv[i] != NULL;i++) {
            msg = stradd(msg, "        \""); msg = stradd(msg, __itoa(i)); msg = stradd(msg, "\": ");
            msg = stradd_quotelast(msg, argv[i]);
            if(argv[i+1] == NULL)
                msg = stradd(msg, "\n");
            else
                msg = stradd(msg, ",\n");
        }
        msg = stradd(msg, "    },\n");
    } else {
        msg = stradd(msg, "    \"args\": {},\n");
    }

    // TODO env

    // DELETE last comma
    size_t len = strlen(msg);
    for(size_t l = len-1;l>0;l--) {
        if(msg[l] == ',') {
            msg[l] = ' ';
            break;
        }
    }

    msg = stradd(msg, "}");

    const char* a_port = getenv(SERVER_PORT_ENVNAME);
    const char* a_path = getenv(SERVER_PATH_ENVNAME);
    if(a_port == NULL && a_path == NULL) {
        printf("bad environment variable, "
               "at least one of %s and %s should set by parent process\n"
               "which provide service to collect process information\n", SERVER_PORT_ENVNAME, SERVER_PATH_ENVNAME);
        return 0;
    }

    uint16_t port = 0;
    if(a_port && strlen(a_port) > 0) port = htons(atoi(a_port));

    int r = 0;

    int errno_save = errno;
    errno = 0;
    if(a_path && strlen(a_path) > 0) {
        r = __sendmsg_unix(msg, strlen(msg), a_path);
    } else if (port > 0) {
        r = __sendmsg_inet(msg, strlen(msg), port, LOCALHOST_ADDR);
    }
    if(errno != 0) {
        // report error
        printf("libccat error: %s\n", strerror(errno));
    }

    errno = errno_save;
    free(msg);
    return r;
} //}
int send_fork(pid_t ppid, pid_t pid, const char* cmd, char* const argv[], char* const env[]) //{
{
    DEBUG();
    return send_generic("fork", ppid, pid, cmd, argv, env);
} //}
int send_exec(pid_t pid, const char* cmd, char* const argv[], char* const env[]) //{
{
    DEBUG();
    assert(cmd != NULL); // TODO
    assert(argv != NULL);
    printf("cmd %s\n", cmd);
    assert(argv[0] != NULL);
    return send_generic("exec", -1, pid, cmd, argv, env ? env : environ);
} //}

