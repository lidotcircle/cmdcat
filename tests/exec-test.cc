#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <signal.h>
#include <wait.h>
#include <stdarg.h>
#include <string.h>

#include "config.h"

// #define DEBUG() printf("exectest call %s\n", __func__)
#define DEBUG()
#define MSG_PREFIX "libccat: "

static void error() {
    DEBUG();
    printf("wrong\n");
    exit(1);
}

static void print_argv(const char* banner, const char* const argv[]) //{
{
    printf("------- dump %s --------\n", banner);
    const char* arg = argv[0];
    size_t i = 0;
    for(;arg!=NULL;i++, arg=argv[i])
        printf("%s\n", arg);
    printf("------- end dump %s --------\n", banner);
} //}
static char* const* getargv(const char* arg0, ...) //{
{
    char** ans = (char**)malloc(sizeof(char*) * 2);
    size_t n = 0;

    char* first = (char*)malloc(strlen(arg0) + 1);
    memcpy(first, arg0, strlen(arg0));
    first[strlen(arg0)] = 0;
    ans[n++] = first;
    ans[n]   = nullptr;

    va_list args;
    va_start(args, arg0);

    while(true) {
        const char* v = va_arg(args, const char*);
        if(v == nullptr)
            break;

        size_t l = strlen(v);
        char* m = (char*)malloc(l + 1);
        memcpy(m, v, l);
        m[l] = 0;

        ans = (char**)realloc(ans, (n + 2) * sizeof(char*));
        ans[n] = m;

        n++;
        ans[n] = nullptr;
    }

    va_end(args);
    return ans;
} //}
static void free_argv(char* const argv[]) //{
{
    char* arg = argv[0];
    for(size_t i=0;arg!=nullptr;i++, arg=argv[i])
        free(arg);
    free((void*)argv);
} //}

static int nchild = 0;

#if !defined(HAVE_FORK) || !defined(HAVE_EXECVE)
#error "fork() and execve() is necessary"
#endif

void try_fork() //{
{
    DEBUG();
    pid_t pid;
    if((pid = fork()) < 0) {
        error();
    } else if (pid == 0){
        printf(MSG_PREFIX "fork() OK\n");
        exit(0);
    }
    nchild++;
} //}
#ifdef HAVE_VFORK
void try_vfork() //{
{
    DEBUG();
    pid_t pid;
    if((pid = vfork()) < 0) {
        error();
    } else if (pid == 0){
        printf(MSG_PREFIX "vfork() OK\n");
        exit(0);
    }
    nchild++;
} //}
#endif

#define __fork() \
    DEBUG(); \
    pid_t pid; \
    if((pid = fork()) < 0) { \
        error(); \
    } else if (pid > 0){ \
        nchild++; \
        return; \
    }

#ifdef HAVE_EXECL
void try_execl() //{
{
    __fork();

    execl("/usr/bin/sh", "/usr/bin/sh", "-c", "echo " "'" MSG_PREFIX "execl() '$TESTME", (char*)NULL);
    assert(false && "what");
} //}
#endif

#ifdef HAVE_EXECLE
void try_execle() //{
{
    __fork();

    execle("/usr/bin/sh", "/usr/bin/sh", "-c", "echo " "'" MSG_PREFIX "execle() '$TESTME", (char*)NULL, environ);
    assert(false && "what");
} //}
#endif

#ifdef HAVE_EXECLP
void try_execlp() //{
{
    __fork();

    execlp("/usr/bin/sh", "/usr/bin/sh", "-c", "echo " "'" MSG_PREFIX "execlp() '$TESTME", (char*)NULL);
    assert(false && "what");
} //}
#endif

#ifdef HAVE_EXECT
void try_exect() //{
{
    __fork();

    auto argv = getargv("/usr/bin/sh", "-c", "echo " "'" MSG_PREFIX "exect() '$TESTME", (char*)NULL);
    exect("/usr/bin/sh", argv, environ);
    free_argv(argv);
    assert(false && "what");
} //}
#endif

#ifdef HAVE_EXECV
void try_execv() //{
{
    __fork();

    auto argv = getargv("/usr/bin/sh", "-c", "echo '" MSG_PREFIX "execv() '$TESTME", (char*)NULL);
    execv("/usr/bin/sh", argv);
    free_argv(argv);
    assert(false && "what");
} //}
#endif

#ifdef HAVE_EXECVP
void try_execvp() //{
{
    __fork();

    auto argv = getargv("/usr/bin/sh", "-c", "echo " "'" MSG_PREFIX "execvp() '$TESTME", (char*)NULL);
    execvp("/usr/bin/sh", argv);
    free_argv(argv);
    assert(false && "what");
} //}
#endif

#ifdef HAVE_EXECVP2
void try_execvP() //{
{
    __fork();

    auto argv = getargv("sh", "-c", "echo " "'" MSG_PREFIX "execvP() '$TESTME", (char*)NULL);
    execvP("sh", "/usr/bin", argv);
    free_argv(argv);
    assert(false && "what");
} //}
#endif

void try_execve() //{
{
    __fork();

    auto argv = getargv("/usr/bin/sh", "-c", "echo " "'" MSG_PREFIX "execve() '$TESTME", (char*)NULL);
    execve("/usr/bin/sh", argv, environ);
    free_argv(argv);
    assert(false && "what");
} //}

#ifdef HAVE_EXECVPE
void try_execvpe() //{
{
    __fork();

    auto argv = getargv("/usr/bin/sh", "-c", "echo " "'" MSG_PREFIX "execvpe() '$TESTME", (char*)NULL);
    execvpe("/usr/bin/sh", argv, environ);
    free_argv(argv);
    assert(false && "what");
} //}
#endif


#ifdef HAVE_POSIX_SPAWN
#include <spawn.h>
#endif

#ifdef HAVE_CLONE3
#include <sched.h>
#endif


int main() {
    printf("----- exec() and fork() wrapper test ------\n");
    fflush(stdout);
    setenv("TESTME", "OK", 1);

    try_fork();

#ifdef HAVE_VFORK
    try_vfork();
#endif

#ifdef HAVE_EXECL
    try_execl();
#endif

#ifdef HAVE_EXECLE
    try_execle();
#endif

#ifdef HAVE_EXECLP
    try_execlp();
#endif

#ifdef HAVE_EXECT
    try_exect();
#endif

#ifdef HAVE_EXECV
    try_execv();
#endif

#ifdef HAVE_EXECVP
    try_execvp();
#endif

#ifdef HAVE_EXECVP2
    try_execvP();
#endif

    try_execve();

#ifdef HAVE_EXECVPE
    try_execvpe();
#endif

    while(nchild) {
        int status;
        int pid = waitpid(-1, &status, 0);
        nchild--;
    }

    return 0;
}

