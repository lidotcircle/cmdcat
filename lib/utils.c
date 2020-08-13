/** GPLv3 see COPYING */
/** this file is modified from libear/ear.c, see https://github.com/rizsotto/Bear */

#include "utils.h"
#include "cmdcat.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


char const **string_array_from_varargs(char const *const arg, va_list *args) //{
{
    char const **result = 0;
    size_t size = 0;
    for (char const *it = arg; it; it = va_arg(*args, char const *)) {
        result = (char const**)realloc(result, (size + 1) * sizeof(char const *));
        if (0 == result)
            ERROR_AND_EXIT("realloc");
        char const *copy = strdup(it);
        if (0 == copy)
            ERROR_AND_EXIT("strdup");
        result[size++] = copy;
    }
    result = (char const**)realloc(result, (size + 1) * sizeof(char const *));
    if (0 == result)
        ERROR_AND_EXIT("realloc");
    result[size++] = 0;

    return result;
} //}
char const **string_array_copy(char const **const in) //{
{
    size_t const size = string_array_length(in);

    char const **const result = (char const**const)malloc((size + 1) * sizeof(char const *));
    if (0 == result)
        ERROR_AND_EXIT("malloc");

    char const **out_it = result;
    for (char const *const *in_it = in; (in_it) && (*in_it);
         ++in_it, ++out_it) {
        *out_it = strdup(*in_it);
        if (0 == *out_it)
            ERROR_AND_EXIT("strdup");
    }
    *out_it = 0;
    return result;
} //}
size_t string_array_length(char const *const *const in) //{
{
    size_t result = 0;
    for (char const *const *it = in; (it) && (*it); ++it)
        ++result;
    return result;
} //}
void string_array_release(char const **in) //{
{
    for (char const *const *it = in; (it) && (*it); ++it) {
        free((void *)*it);
    }
    free((void *)in);
} //}
char const **string_array_partial_update(char *const envp[], env_t *env) //{
{
    char const **result = string_array_copy((char const **)envp);
    for (size_t it = 0; it < ENV_SIZE && (*env)[it]; ++it)
        result = string_array_single_update(result, env_names[it], (*env)[it]);
    return result;
} //}
char const **string_array_single_update(char const *envs[], char const *key, char const * const value) //{
{
    // find the key if it's there
    size_t const key_length = strlen(key);
    char const **it = envs;
    for (; (it) && (*it); ++it) {
        if ((0 == strncmp(*it, key, key_length)) &&
            (strlen(*it) > key_length) && ('=' == (*it)[key_length]))
            break;
    }
    // allocate a environment entry
    size_t const value_length = strlen(value);
    size_t const env_length = key_length + value_length + 2;
    char *env = (char*)malloc(env_length);
    if (0 == env)
        ERROR_AND_EXIT("malloc");
    if (-1 == snprintf(env, env_length, "%s=%s", key, value))
        ERROR_AND_EXIT("snprintf");
    // replace or append the environment entry
    if (it && *it) {
        free((void *)*it);
        *it = env;
	    return envs;
    } else {
        size_t const size = string_array_length(envs);
        char const **result = (char const**)realloc(envs, (size + 2) * sizeof(char const *));
        if (0 == result)
            ERROR_AND_EXIT("realloc");
        result[size] = env;
        result[size + 1] = 0;
        return result;
    }
} //}


void report_exec_call(pid_t pid, const char* filename, char* const argv[], char* const envp[]) //{
{
    int t = argv[0] ? 1 : 0;
    send_exec(pid, filename, t ? argv + 1 : argv, envp);

    if(avail_socket > 0) {
        close(avail_socket);
        avail_socket = 0;
    }
} //}
void report_fork_call(pid_t ppid, pid_t pid) //{
{
    send_fork(ppid, pid, NULL, NULL, NULL);
} //}

void print_string_array(const char* banner, const char* const argv[]) //{
{
    printf("------- [%d] dump %s --------\n", getpid(), banner);
    const char* arg = argv[0];
    size_t i = 0;
    for(;arg!=NULL;i++, arg=argv[i])
        printf("%s\n", arg);
    printf("------- [%d] end dump %s --------\n", getpid(), banner);
} //}

