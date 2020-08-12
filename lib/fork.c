/** GPLv3 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>

#include "config.h"
#include "utils.h"


#ifdef HAVE_FORK
static int call_fork() {
    DEBUG();
    typedef int (*forktype)(void);
    DLSYM(forktype, __fork, "fork");
    return __fork();
}
int fork() {
    DEBUG();
    int r = call_fork();
    // TODO
    if(r == 0) {
        if(avail_socket > 0) {
            close(avail_socket);
            avail_socket = 0;
        }
        report_fork_call(getppid(), getpid());
    }
    return r;
}
#endif


#ifdef HAVE_VFORK
static int call_vfork() {
    DEBUG();
    typedef int (*vforktype)(void);
    DLSYM(vforktype, __vfork, "vfork");
    return __vfork();
}
// FIXME
int vfork() {
    DEBUG();
    int r = call_fork();
    if(r == 0) {
        if(avail_socket > 0) {
            close(avail_socket);
            avail_socket = 0;
        }
        report_fork_call(getppid(), getpid());
    }
    return r;
}
#endif

#ifdef HAVE_CLONE
// TODO
#endif

#ifdef HAVE_CLONE3
static int call_clone3(struct clone_args* cl_args, size_t size) {
    DEBUG();
    typedef long (*clone3type)(struct clone_args* cl_args, size_t size);
    DLSYM(clone3type, __clone3, "clone3");

    return __clone3(cl_args, size);
}
long clone3(struct clone_args* cl_args, size_t size) {
    DEBUG();
    long r = call_clone3(cl_args, size);
    if(r == 0)
        report_fork_call(getppid(), getpid());
    return r;
}
#endif

