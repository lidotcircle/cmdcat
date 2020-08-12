#pragma once

#include <unistd.h>
#define __GNU_SOURCE

#ifdef __BIG_ENDIAN__
#define LOCALHOST_ADDR (0x7f000001)
#else
#define LOCALHOST_ADDR (0x0100007f)
#endif

#define SERVER_PORT_ENVNAME "SERVER_PORT"
#define SERVER_PATH_ENVNAME "SERVER_PATH"


#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

int send_fork(pid_t ppid, pid_t pid, const char* cmd, char* const argv[], char* const env[]);
int send_exec(pid_t pid, const char* cmd, char* const argv[], char* const env[]);

#ifdef __cplusplus
}
#endif // __cplusplus

