/** GPLv3 */
/** this file is modified from libear/ear.c, see https://github.com/rizsotto/Bear */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>

#include "config.h"
#include "utils.h"

#if defined HAVE_POSIX_SPAWN || defined HAVE_POSIX_SPAWNP
#include <spawn.h>
#endif


/* These are the methods which forward the call to the standard implementation. */

#ifdef HAVE_EXECVE
static int call_execve(const char *path, char *const argv[],
                       char *const envp[]) {
    DEBUG();
    typedef int (*func)(const char *, char *const *, char *const *);

    DLSYM(func, fp, "execve");

    char const **const menvp = string_array_partial_update(envp, &initial_env);
    int const result = (*fp)(path, argv, (char *const *)menvp);
    string_array_release(menvp);
    return result;
}
#endif

#ifdef HAVE_EXECVPE
static int call_execvpe(const char *file, char *const argv[],
                        char *const envp[]) {
    DEBUG();
    typedef int (*func)(const char *, char *const *, char *const *);

    DLSYM(func, fp, "execvpe");

    char const **const menvp = string_array_partial_update(envp, &initial_env);
    int const result = (*fp)(file, argv, (char *const *)menvp);
    string_array_release(menvp);
    return result;
}
#endif

#ifdef HAVE_EXECVP
static int call_execvp(const char *file, char *const argv[]) {
    DEBUG();
    typedef int (*func)(const char *file, char *const argv[]);

    DLSYM(func, fp, "execvp");

    char **const original = environ;
    char const **const modified = string_array_partial_update(original, &initial_env);
    environ = (char **)modified;
    int const result = (*fp)(file, argv);
    environ = original;
    string_array_release(modified);

    return result;
}
#endif

#ifdef HAVE_EXECVP2
static int call_execvP(const char *file, const char *search_path,
                       char *const argv[]) {
    DEBUG();
    typedef int (*func)(const char *, const char *, char *const *);

    DLSYM(func, fp, "execvP");

    char **const original = environ;
    char const **const modified = string_array_partial_update(original, &initial_env);
    environ = (char **)modified;
    int const result = (*fp)(file, search_path, argv);
    environ = original;
    string_array_release(modified);

    return result;
}
#endif

#ifdef HAVE_EXECT
static int call_exect(const char *path, char *const argv[],
                      char *const envp[]) {
    DEBUG();
    typedef int (*func)(const char *, char *const *, char *const *);

    DLSYM(func, fp, "exect");

    char const **const menvp = string_array_partial_update(envp, &initial_env);
    int const result = (*fp)(path, argv, (char *const *)menvp);
    string_array_release(menvp);
    return result;
}
#endif

#ifdef HAVE_POSIX_SPAWN
static int call_posix_spawn(pid_t * pid, const char * path,
                            const posix_spawn_file_actions_t *file_actions,
                            const posix_spawnattr_t * attrp,
                            char *const argv[],
                            char *const envp[]) {
    DEBUG();
    typedef int (*func)(pid_t *, const char *,
                        const posix_spawn_file_actions_t *,
                        const posix_spawnattr_t *,
                        char *const *, char *const *);

    DLSYM(func, fp, "posix_spawn");

    char const **const menvp = string_array_partial_update(envp, &initial_env);
    int const result =
        (*fp)(pid, path, file_actions, attrp, argv, (char *const *)menvp);
    string_array_release(menvp);
    return result;
}
#endif

#ifdef HAVE_POSIX_SPAWNP
static int call_posix_spawnp(pid_t * pid, const char * file,
                             const posix_spawn_file_actions_t *file_actions,
                             const posix_spawnattr_t * attrp,
                             char *const argv[],
                             char *const envp[]) {
    DEBUG();
    typedef int (*func)(pid_t *, const char *,
                        const posix_spawn_file_actions_t *,
                        const posix_spawnattr_t *,
                        char *const *, char *const *);

    DLSYM(func, fp, "posix_spawnp");

    char const **const menvp = string_array_partial_update(envp, &initial_env);
    int const result =
        (*fp)(pid, file, file_actions, attrp, argv, (char *const *)menvp);
    string_array_release(menvp);
    return result;
}
#endif


/** These are the methods we are try to hijack. */

#ifdef HAVE_EXECVE
int execve(const char *path, char *const argv[], char *const envp[]) {
    DEBUG();
    report_exec_call(getpid(), path, argv, envp);
    return call_execve(path, argv, envp);
}
#endif

#ifdef HAVE_EXECV
#ifndef HAVE_EXECVE
#error can not implement execv without execve
#endif
int execv(const char *path, char *const argv[]) {
    DEBUG();
    report_exec_call(getpid(), path, argv, environ);
    return call_execve(path, argv, environ);
}
#endif

#ifdef HAVE_EXECVPE
int execvpe(const char *file, char *const argv[], char *const envp[]) {
    DEBUG();
    report_exec_call(getpid(), file, argv, envp);
    return call_execvpe(file, argv, envp);
}
#endif

#ifdef HAVE_EXECVP
int execvp(const char *file, char *const argv[]) {
    DEBUG();
    report_exec_call(getpid(), file, argv, NULL);
    return call_execvp(file, argv);
}
#endif

#ifdef HAVE_EXECVP2
int execvP(const char *file, const char *search_path, char *const argv[]) {
    DEBUG();
    report_exec_call(getpid(), file, argv, NULL);
    return call_execvP(file, search_path, argv);
}
#endif

#ifdef HAVE_EXECT
int exect(const char *path, char *const argv[], char *const envp[]) {
    DEBUG();
    report_exec_call(getpid(), path, argv, envp);
    return call_exect(path, argv, envp);
}
#endif

#include <string.h>
#include <errno.h>
#ifdef HAVE_EXECL
# ifndef HAVE_EXECVE
#  error can not implement execl without execve
# endif
int execl(const char *path, const char *arg, ...) {
    DEBUG();
    va_list args;
    va_start(args, arg);
    char const **argv = string_array_from_varargs(arg, &args);
    va_end(args);

    report_exec_call(getpid(), path, (char*const*)argv, NULL);
    int const result = call_execve(path, (char *const *)argv, environ);

    string_array_release(argv);
    return result;
}
#endif

#ifdef HAVE_EXECLP
# ifndef HAVE_EXECVP
#  error can not implement execlp without execvp
# endif
int execlp(const char *file, const char *arg, ...) {
    DEBUG();
    va_list args;
    va_start(args, arg);
    char const **argv = string_array_from_varargs(arg, &args);
    va_end(args);

    report_exec_call(getpid(), file, (char*const*)argv, NULL);
    int const result = call_execvp(file, (char *const *)argv);

    string_array_release(argv);
    return result;
}
#endif

#ifdef HAVE_EXECLE
# ifndef HAVE_EXECVE
#  error can not implement execle without execve
# endif
// int execle(const char *path, const char *arg, ..., char * const envp[]);
int execle(const char *path, const char *arg, ...) {
    DEBUG();
    va_list args;
    va_start(args, arg);
    char const **argv = string_array_from_varargs(arg, &args);
    char const **envp = va_arg(args, char const **);
    va_end(args);

    report_exec_call(getpid(), path, (char*const*)argv, (char*const*)envp);
    int const result =
        call_execve(path, (char *const *)argv, (char *const *)envp);

    string_array_release(argv);
    return result;
}
#endif

#ifdef HAVE_POSIX_SPAWN
int posix_spawn(pid_t * pid, const char * path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t * attrp,
                char *const argv[], char *const envp[]) {
    DEBUG();
    int r = call_posix_spawn(pid, path, file_actions, attrp, argv, envp);
    if(r == 0) {
        report_fork_call(getpid(), *pid);
        report_exec_call(*pid, path, argv, envp);
    }
    return r;
}
#endif

#ifdef HAVE_POSIX_SPAWNP
int posix_spawnp(pid_t * pid, const char * file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t * attrp,
                 char *const argv[], char *const envp[]) {
    DEBUG();
    int r = call_posix_spawnp(pid, file, file_actions, attrp, argv, envp);
    if(r == 0) {
        report_fork_call(getpid(), *pid);
        report_exec_call(*pid, file, argv, envp);
    }
    return r;
}
#endif

/*
static void on_load() __attribute__((constructor));

#define TEST_FUNC(func) \
    { \
        DLSYM(void*, abc, #func); \
        printf(#func " libc: 0x%lx, wrapper: 0x%lx\n", (long)abc, (long)func); \
    }
static void on_load() //{
{
    TEST_FUNC(fork);
    TEST_FUNC(vfork);
    TEST_FUNC(execve);
    TEST_FUNC(execl);
} //}
*/

