#pragma once

#include "config.h"
#include "cmdcat.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#if defined HAVE_NSGETENVIRON
# include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
extern char **environ;
#endif

/* #define SERVER_PORT_ENVNAME "SERVER_PORT" */
#ifdef APPLE
# define ENV_FLAT    "DYLD_FORCE_FLAT_NAMESPACE"
# define ENV_PRELOAD "DYLD_INSERT_LIBRARIES"
# define ENV_SIZE 3
#else
# define ENV_PRELOAD "LD_PRELOAD"
# define ENV_SIZE 2
#endif

typedef char const * bear_env_t[ENV_SIZE];

extern bear_env_t env_names;
extern bear_env_t initial_env;

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT "libccat : (" __FILE__ ":" TOSTRING(__LINE__) ") "
#define PERROR(msg)         do { fprintf(stderr, "[%i]", getpid()); perror(AT msg); } while (0)
#define ERROR_AND_EXIT(msg) do { PERROR(msg); exit(EXIT_FAILURE); } while (0)

#define DLSYM(TYPE_, VAR_, SYMBOL_)                                 \
    union {                                                         \
        void *from;                                                 \
        TYPE_ to;                                                   \
    } cast;                                                         \
    if (0 == (cast.from = dlsym(RTLD_NEXT, SYMBOL_))) {             \
        PERROR("dlsym");                                            \
        exit(EXIT_FAILURE);                                         \
    }                                                               \
    TYPE_ const VAR_ = cast.to;


char const **string_array_from_varargs(char const * arg, va_list *args);
char const **string_array_copy(char const **in);
size_t       string_array_length(char const *const *in);
void         string_array_release(char const **);
char const **string_array_partial_update(char *const envp[], bear_env_t *env);
char const **string_array_single_update(char const *envs[], char const *key, char const *value);

void report_exec_call(pid_t pid,  const char* file, char *const argv[], char *const envp[]);
void report_fork_call(pid_t ppid, pid_t pid);

void print_string_array(const char* banner, const char* const argv[]);

// #define DEBUG() printf("call %s\n", __func__)
#define DEBUG()

