#pragma once

#include <unistd.h>
#define __GNU_SOURCE

#ifdef __BIG_ENDIAN__
#define LOCALHOST_ADDR (0x7f000001)
#else
#define LOCALHOST_ADDR (0x0100007f)
#endif

#ifdef APPLE
#define ENV_FLAT    "DYLD_FORCE_FLAT_NAMESPACE"
#define ENV_PRELOAD "DYLD_INSERT_LIBRARIES"
#define ENV_SIZE 6
#else
#define ENV_PRELOAD "LD_PRELOAD"
#define ENV_SIZE 5
#endif

#define SERVER_PORT_ENVNAME   "SERVER_PORT"
#define SERVER_PATH_ENVNAME   "SERVER_PATH"
#define SERVER_DOMAIN_ENVNAME "SERVER_DOMAIN"
#define SERVER_TYPE_ENVNAME   "SERVER_TYPE"

#define MAX_MESSAGE_SIZE 4096


#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

int send_fork(pid_t ppid, pid_t pid, const char* cmd, char* const argv[], char* const env[]);
int send_exec(pid_t pid, const char* cmd, char* const argv[], char* const env[]);

#ifdef __cplusplus
}
#endif // __cplusplus

