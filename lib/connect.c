#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>

#include "cmdcat.h"
#include "utils.h"

env_t env_names = {
    ENV_PRELOAD,
    SERVER_PATH_ENVNAME,
    SERVER_PORT_ENVNAME,
    SERVER_DOMAIN_ENVNAME,
    SERVER_TYPE_ENVNAME
#ifdef APPLE
    ENV_FLAT,
#endif
};
env_t env_values = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#ifdef APPLE
    NULL,
#endif
};

int avail_socket = 0;
static int initialized = 0;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int  socket_domain    = AF_UNIX;
static int  socket_type      = SOCK_STREAM;
static uint16_t connect_port = 0;
static char connect_path[sizeof(struct sockaddr_un)] = {0};

const char *preload_library = NULL;

static void on_load()   __attribute__((constructor));
static void on_unload() __attribute__((destructor));
static void on_load() //{
{
    DEBUG();
    if(initialized) return;
    pthread_mutex_lock(&mutex);
    for(size_t i=0;i<ENV_SIZE;i++) {
        const char* e = getenv(env_names[i]);
        if(e == NULL) {
            fprintf(stderr, "require environment variable '%s'\n", env_names[i]);
            exit(1);
        } else {
            char* a = (char*)malloc(strlen(e) + 1);
            memcpy(a, e, strlen(e));
            env_values[i] = a;
            env_values[strlen(e)] = 0;
        }
    }

    const char* a_port  = env_values[2];
    const char* a_path  = env_values[1];
    const char* domain  = env_values[3];
    const char* type    = env_values[4];
    const char* preload = env_values[0];
    // TODO APPLE

    if(memcmp(domain, "AF_INET", strlen(domain)) == 0) {
        socket_domain = AF_INET;
    } else if(memcmp(domain, "AF_UNIX",  strlen(domain)) == 0 || 
              memcmp(domain, "AF_LOCAL", strlen(domain)) == 0) {
        socket_domain = AF_UNIX;
    } else {
        fprintf(stderr, "bad " SERVER_DOMAIN_ENVNAME ", should be 'AF_INET' or 'AF_UNIX' or 'AF_LOCAL'\n");
        exit(1);
    }

    if(memcmp(type, "SOCK_DGRAM", strlen(type)) == 0) {
        socket_type = SOCK_DGRAM;
    } else if(memcmp(type, "SOCK_STREAM",  strlen(type)) == 0) {
        socket_type = SOCK_STREAM;
    } else {
        fprintf(stderr, "bad " SERVER_TYPE_ENVNAME ", should be 'SOCK_STREAM' or 'SOCK_DGRAM'\n");
        exit(1);
    }

    if(a_port == 0 && strlen(a_path) == 0) {
        fprintf(stderr, "bad port and path\n");
        exit(1);
    }
    if(a_port) connect_port = htons(atoi(a_port));
    if(a_path) strcpy(connect_path, a_path);

    preload_library = env_names[0];

    initialized = 1;
    pthread_mutex_unlock(&mutex);
} //}
static void on_unload() //{
{
    DEBUG();
    preload_library = NULL;

    for(size_t i=0;i<ENV_SIZE;i++) {
        free((char*)env_values[i]);
        env_values[i] = NULL;
    }

    if(avail_socket > 0) {
        close(avail_socket);
        avail_socket = 0;
    }
    initialized = 0;
} //}


static int __sendmsg(const char* buf, size_t len) //{
{
    DEBUG();
    if(strlen(buf) + 2 > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "message too large to send\n");
        return 0;
    }

    pthread_mutex_lock(&mutex);
    int r = 0;

    if(avail_socket <= 0) {
        int prot = 0;
        if(socket_domain == AF_INET) {
            if(socket_type == SOCK_DGRAM)
                prot = IPPROTO_UDP;
            else
                prot = IPPROTO_TCP;
        }
        avail_socket = socket(socket_domain, socket_type, prot);
        if(avail_socket <= 0) goto RETURN;

    }
    assert(avail_socket > 0);

    struct sockaddr_storage dest;
    socklen_t sl = 0;
    if(socket_domain == AF_INET) {
        assert(connect_port > 0);
        struct sockaddr_in* addr_in = (struct sockaddr_in*)&dest;
        addr_in->sin_family = AF_INET;
        addr_in->sin_addr.s_addr = LOCALHOST_ADDR;
        addr_in->sin_port = connect_port;
        sl = sizeof(*addr_in);
    } else {
        assert(socket_domain == AF_UNIX);
        assert(connect_path != NULL && strlen(connect_path) > 0);
        struct sockaddr_un* addr_un = (struct sockaddr_un*)&dest;
        addr_un->sun_family = AF_UNIX;
        strcpy(addr_un->sun_path, connect_path);
        sl = sizeof(*addr_un);
    }
    if(socket_type != SOCK_DGRAM) {
        if(connect(avail_socket, (struct sockaddr*)&dest, sl) < 0) {
            close(avail_socket);
            avail_socket = 0;
            goto RETURN;
        }
    }
    assert(avail_socket > 0);

    if(socket_type == SOCK_STREAM) {
        char lenbuf[2];
        *((uint16_t*)lenbuf) = htons(len);
        if(send(avail_socket, lenbuf, sizeof(lenbuf), 0) != sizeof(lenbuf)) {
            close(avail_socket);
            avail_socket = 0;
            goto RETURN;
        }

        if(send(avail_socket, buf, len, 0) == len) {
            close(avail_socket);
            avail_socket = 0;
            goto RETURN;
        }
    } else {
        if(sendto(avail_socket, buf, len , 0, (struct sockaddr*)&dest, sl) != len) {
            close(avail_socket);
            avail_socket = 0;
            goto RETURN;
        }
    }

    r = 1;
RETURN:
    pthread_mutex_unlock(&mutex);
    return r;
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

static const char* escape_character_table[] = //{
{
    "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\\a" ,
    "\\b",  "\\t",  "\\n",  "\\v",  "\\f",  "\\r",  "\x0e", "\x0f",
    "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17",
    "\x18", "\x19", "\x1a", "\\e",  "\x1c", "\x1d", "\x1e", "\x1f",
    "\x20", "\x21", "\\\"", "\x23", "\x24", "\x25", "\x26", "\x27",
    "\x28", "\x29", "\x2a", "\x2b", "\x2c", "\x2d", "\x2e", "\x2f",
    "\x30", "\x31", "\x32", "\x33", "\x34", "\x35", "\x36", "\x37",
    "\x38", "\x39", "\x3a", "\x3b", "\x3c", "\x3d", "\x3e", "\x3f" ,
    "\x40", "\x41", "\x42", "\x43", "\x44", "\x45", "\x46", "\x47",
    "\x48", "\x49", "\x4a", "\x4b", "\x4c", "\x4d", "\x4e", "\x4f",
    "\x50", "\x51", "\x52", "\x53", "\x54", "\x55", "\x56", "\x57",
    "\x58", "\x59", "\x5a", "\x5b", "\\\\", "\x5d", "\x5e", "\x5f",
    "\x60", "\x61", "\x62", "\x63", "\x64", "\x65", "\x66", "\x67",
    "\x68", "\x69", "\x6a", "\x6b", "\x6c", "\x6d", "\x6e", "\x6f",
    "\x70", "\x71", "\x72", "\x73", "\x74", "\x75", "\x76", "\x77",
    "\x78", "\x79", "\x7a", "\x7b", "\x7c", "\x7d", "\x7e", "\x7f",
    "\x80", "\x81", "\x82", "\x83", "\x84", "\x85", "\x86", "\x87",
    "\x88", "\x89", "\x8a", "\x8b", "\x8c", "\x8d", "\x8e", "\x8f",
    "\x90", "\x91", "\x92", "\x93", "\x94", "\x95", "\x96", "\x97",
    "\x98", "\x99", "\x9a", "\x9b", "\\\\", "\x9d", "\x9e", "\x9f",
    "\xa0", "\xa1", "\xa2", "\xa3", "\xa4", "\xa5", "\xa6", "\xa7",
    "\xa8", "\xa9", "\xaa", "\xab", "\xac", "\xad", "\xae", "\xaf",
    "\xb0", "\xb1", "\xb2", "\xb3", "\xb4", "\xb5", "\xb6", "\xb7",
    "\xb8", "\xb9", "\xba", "\xbb", "\xbc", "\xbd", "\xbe", "\xbf",
    "\xc0", "\xc1", "\xc2", "\xc3", "\xc4", "\xc5", "\xc6", "\xc7",
    "\xc8", "\xc9", "\xca", "\xcb", "\xcc", "\xcd", "\xce", "\xcf",
    "\xd0", "\xd1", "\xd2", "\xd3", "\xd4", "\xd5", "\xd6", "\xd7",
    "\xd8", "\xd9", "\xda", "\xdb", "\\\\", "\xdd", "\xde", "\xdf",
    "\xe0", "\xe1", "\xe2", "\xe3", "\xe4", "\xe5", "\xe6", "\xe7",
    "\xe8", "\xe9", "\xea", "\xeb", "\xec", "\xed", "\xee", "\xef",
    "\xf0", "\xf1", "\xf2", "\xf3", "\xf4", "\xf5", "\xf6", "\xf7",
    "\xf8", "\xf9", "\xfa", "\xfb", "\xfc", "\xfd", "\xfe", "\xff",
}; //}
static char* double_quote_string(const char* str) //{
{
    size_t len = strlen(str);
    char* result = (char*)malloc(len * 2 + 2);
    size_t pos = 0;
    result[pos++] = '"';
    for(size_t i=0;i<len;i++) {
        unsigned char c = str[i];

        const char* s = escape_character_table[c];
        for(size_t j=0;j<strlen(s);j++)
            result[pos++] = s[j];
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

    if(env != NULL) {
        msg = stradd(msg, "    \"envs\": [\n");
        for(int i=0;env[i] != NULL;i++) {
            msg = stradd(msg, "        ");
            msg = stradd_quotelast(msg, env[i]);
            if(env[i+1] == NULL)
                msg = stradd(msg, "\n");
            else
                msg = stradd(msg, ",\n");
        }
        msg = stradd(msg, "    ],\n");
    } else {
        msg = stradd(msg, "    \"envs\": {},\n");
    }

    char buf[512];
    if(getcwd(buf, sizeof(buf)) != NULL) {
        msg = stradd(msg, "    \"cwd\":");
        msg = stradd_quotelast(msg, buf);
        msg = stradd(msg, ",\n");
    }

    // DELETE last comma
    size_t len = strlen(msg);
    for(size_t l = len-1;l>0;l--) {
        if(msg[l] == ',') {
            msg[l] = ' ';
            break;
        }
    }

    msg = stradd(msg, "}");

    int r = 0;
    int errno_save = errno;
    errno = 0;

    r = __sendmsg(msg, strlen(msg));

    if(errno != 0) {
        // report error
        fprintf(stderr, "libccat error: %s\n", strerror(errno));
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
    assert(cmd != NULL && argv != NULL);
    return send_generic("exec", -1, pid, cmd, argv, env ? env : environ);
} //}

