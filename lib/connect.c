#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include "cmdcat.h"
#include "utils.h"

static int __sendmsg(const char* buf, size_t len, uint16_t port, uint32_t addr) //{
{
    DEBUG();
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(fd < 0) return 0;

    struct sockaddr_in s_addr;
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = addr;
    s_addr.sin_port = port;
    if(connect(fd, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0) {
        shutdown(fd, SHUT_RDWR);
        return 0;
    }

    char sizebuf[2];
    *(uint16_t*)sizebuf = htons(len);
    int slen = send(fd, sizebuf, sizeof(sizebuf), 0);
    if(slen != 2) {
        shutdown(fd, SHUT_RDWR);
        return 0;
    }
    slen = send(fd, buf, len, 0);

    shutdown(fd, SHUT_RDWR);
    return slen == len;
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

int send_fork(pid_t ppid, pid_t pid, const char* cmd, char* const argv[], char* const env[]) //{
{
    DEBUG();
    char* msg = strnew(
        "{\n"
        "    \"function\": \"fork\",\n");

    msg = stradd(msg, "    \"ppid\": "); msg = stradd(msg, __itoa(ppid)); msg = stradd(msg, ",\n");
    msg = stradd(msg, "    \"pid\": ");  msg = stradd(msg, __itoa(pid));
    if(cmd == NULL)
        msg = stradd(msg, "\n");
    else
        msg = stradd(msg, ",\n");

    if(cmd != NULL) {
        msg = stradd(msg, "    \"cmd\": \"");
        msg = stradd(msg, cmd);
        msg = stradd(msg, "\",\n");
    }
    if(argv != NULL) {
        assert(cmd != NULL);

        msg = stradd(msg, "    \"args\": {\n");
        for(int i=0;argv[i] != NULL;i++) {
            msg = stradd(msg, "        \""); msg = stradd(msg, __itoa(i)); msg = stradd(msg, "\": ");
            msg = stradd_quotelast(msg, argv[i]);
            if(argv[i+1] == NULL)
                msg = stradd(msg, "\n");
            else
                msg = stradd(msg, ",\n");
        }
        msg = stradd(msg, "    }\n");
    } else if(cmd != NULL) {
        msg = stradd(msg, "    \"args\": {}\n");
    }

    // TODO env

    msg = stradd(msg, "}");

    const char* a_port = getenv(SERVER_PORT_ENVNAME);
    if(a_port == NULL) return 0;
    uint16_t port = htons(atoi(a_port));
    if(port == 0) return 0;

    int r = __sendmsg(msg, strlen(msg), port, LOCALHOST_ADDR);
    free(msg);
    return r;
} //}
int send_exec(pid_t pid, const char* cmd, char* const argv[], char* const env[]) //{
{
    DEBUG();
    assert(cmd != NULL);
    char* msg = strnew(
        "{\n"
        "    \"function\": \"exec\",\n");

    msg = stradd(msg, "    \"pid\": ");  msg = stradd(msg, __itoa(pid));
    if(cmd == NULL)
        msg = stradd(msg, "\n");
    else
        msg = stradd(msg, ",\n");

    msg = stradd(msg, "    \"cmd\": \"");
    msg = stradd(msg, cmd);
    msg = stradd(msg, "\",\n");
    if(argv != NULL) {
        assert(cmd != NULL);

        msg = stradd(msg, "    \"args\": {\n");
        for(int i=0;argv[i] != NULL;i++) {
            msg = stradd(msg, "        \""); msg = stradd(msg, __itoa(i)); msg = stradd(msg, "\": ");
            msg = stradd_quotelast(msg, argv[i]);
            if(argv[i+1] == NULL)
                msg = stradd(msg, "\n");
            else
                msg = stradd(msg, ",\n");
        }
        msg = stradd(msg, "    }\n");
    } else if(cmd != NULL) {
        msg = stradd(msg, "    \"args\": {}\n");
    }

    // TODO env

    msg = stradd(msg, "}");

    const char* a_port = getenv(SERVER_PORT_ENVNAME);
    if(a_port == NULL) return 0;
    uint16_t port = htons(atoi(a_port));
    if(port == 0) return 0;

    int r = __sendmsg(msg, strlen(msg), port, LOCALHOST_ADDR);
    free(msg);
    return r;
} //}

