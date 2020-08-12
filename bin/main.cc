#include "server.h"

#include <signal.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <filesystem>
#include <thread>
#include <chrono>
#include <fstream>

#include "../lib/cmdcat.h"

const char* const library_search_path[] {
    "./",
    "/lib",
    "/usr/lib",
    "/usr/local/lib",
    nullptr
};

static Server* gserver = nullptr;
static bool run__ = true;

static struct options {
    std::string output_file;
    std::string libccat_path;

    bool suppress = false;

    std::string              cmd;
    std::vector<std::string> argv;
} global_options;

static uint32_t    listening_port;
static std::string listening_path;
static pid_t       child_pid;

static void usage();

static int int_signal = 0;
static void int_handle(int sig) //{
{
    assert(sig == SIGINT);
    int_signal = 1;
    run__ = false;
    gserver->stop();
} //}
static void chld_handle(int sig) //{
{
    assert(sig == SIGCHLD);
    run__ = false;
    gserver->stop();
} //}

static void print_environ() //{
{
    size_t i=0;
    const char* env;
    for(env=environ[i];env!=nullptr;i++, env=environ[i])
        std::cout << std::string(env) << std::endl;
} //}

#ifdef APPLE
# define ENV_FLAT    "DYLD_FORCE_FLAT_NAMESPACE"
# define ENV_PRELOAD "DYLD_INSERT_LIBRARIES"
#else
# define ENV_PRELOAD "LD_PRELOAD"
#endif
static void setup_environment_variables() //{
{
    setenv(SERVER_PORT_ENVNAME, std::to_string(listening_port).c_str(), 1);
    setenv(SERVER_PATH_ENVNAME, listening_path.c_str(), 1);
    setenv(ENV_PRELOAD, global_options.libccat_path.c_str(), 1);
    // TODO
} //}
static char* const* get_argv(const std::vector<std::string>& argv) //{
{
    char** ret = (char**)malloc(sizeof(char*) * (argv.size() + 1));

    size_t i=0;
    for(auto& arg: argv) {
        ret[i] = (char*)malloc(arg.size() + 1);
        memcpy(ret[i], arg.c_str(), arg.size());
        ret[i][arg.size()] = 0;
        i++;
    }
    ret[i] = nullptr;

    return ret;
} //}
static void empty_handle(int) {std::cout << "empty handler" << std::endl;}
static void run_command() //{
{
    /*
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGUSR1);
    signal(SIGUSR1, empty_handle);
    int sig;
    int r = sigwait(&sigset, &sig);
    if(r != 0) {
        std::cerr << "sigwait() fail" << std::endl;
        exit(1);
    }
    */
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    assert(global_options.cmd.size() > 0);
    setup_environment_variables();

    auto argv = get_argv(global_options.argv);
    if(execvpe(global_options.cmd.c_str(), argv, environ) < 0) {
        std::cerr << "run \"";
        std::cerr << global_options.cmd;
        for(auto& arg: global_options.argv)
            std::cerr << " " << arg;
        std::cerr << "\"fail" << std::endl;
        exit(1);
    }
    assert(false && "unreachable");
} //}

static const std::map<char, bool> short_options = {
    {'o', true},
    {'l', true},
    {'s', false},
    {'h', false}
};
static const std::map<std::string, bool> long_options = {};
static void handle_option(const std::string& option, const std::string& arg) //{
{
    if(option == "o") {
        if(global_options.output_file.size() > 0) {
            usage();
            std::cerr << "\nduplicated \"-o\" option" << std::endl;
            exit(2);
        } else {
            global_options.output_file = arg;
        }
    } else if (option == "l") {
        if(global_options.libccat_path.size() > 0) {
            usage();
            std::cerr << "\nduplicated \"-l\" option" << std::endl;
            exit(2);
        } else {
            global_options.libccat_path = arg;
        }
    } else if (option == "s") {
        global_options.suppress = true;
    } else if (option == "h" || option == "help") {
        usage();
        exit(0);
    } else {
        std::cerr << "unimplement option '" << option << std::endl;
        exit(2);
    }
} //}
static void parse_argv(const char* const argv[]) //{
{
    using namespace std;
    size_t i=1;
    const char* arg = argv[i];

    for(; arg != nullptr; i++, arg=argv[i]) {
        if(arg[0] == '-' && strlen(arg) > 1) {
            if(arg[1] != '-') {
                size_t len = strlen(arg);
                for(size_t j=1;j<len;j++) {
                    char c = arg[j];
                    if(short_options.find(c) == short_options.end()) {
                        usage();
                        std::cerr << "\nunknown option " << string(arg) << std::endl;
                        exit(2);
                    } else {
                        string option(1, c);
                        string opt_arg = "";
                        const bool has_arg = short_options.find(c)->second;
                        if(has_arg) {
                            if(++j != len || (arg = argv[++i]) == nullptr) {
                                usage();
                                std::cerr << "\noption '-" << string(1, c) << "' require argument" << std::endl;
                                exit(2);
                            }
                            opt_arg = string(arg);
                        }
                        handle_option(option, opt_arg);
                    }
                }
            } else {
                if(long_options.find(string(arg + 2)) == long_options.end()) {
                    usage();
                    std::cerr << "\nunknown option " << string(arg) << std::endl;
                    exit(2);
                }
                string option  = string(arg + 2);
                string opt_arg = "";
                const bool has_arg = long_options.find(string(arg+2))->second;
                if(has_arg) {
                    if((arg = argv[++i]) == nullptr) {
                        usage();
                        std::cerr << "\noption '" << string(arg) << "' require augument" << std::endl;
                        exit(2);
                    }
                    opt_arg = string(arg);
                }
                handle_option(option, opt_arg);
            }
        } else break;
    }

    if(arg == nullptr) {
        usage();
        std::cerr << "command must be specified" << std::endl;
        exit(2);
    }

    global_options.cmd = std::string(arg);
    for(;arg!=nullptr;++i, arg=argv[i])
        global_options.argv.push_back(std::string(arg));
} //}
static void usage() //{
{
    auto usage = 
        "Usage: \n"
        "       cmdcat [-solh] <command>\n"
        "\n"
        "    -s          suppress stdout output\n"
        "    -o <file>   specify output file, default stdout\n"
        "    -l <dir>    directory of libccat\n"
        "    -h          display help\n";
    std::cout << usage;
} //}

#define LIBNAME "libccat.so"
static void search_ccat() //{
{
    if(global_options.libccat_path.size() > 0) {
        if(!std::filesystem::is_regular_file(global_options.libccat_path) &&
           !std::filesystem::is_symlink(global_options.libccat_path)) {
            std::cerr << "file \"" << global_options.libccat_path << "\" doesn't exist" << std::endl;
            exit(3);
        }
        std::error_code error;
        global_options.libccat_path = std::filesystem::canonical(global_options.libccat_path, error);
        assert(!error && "path ... ???");
        return;
    }

    size_t i=0;
    const char* path = library_search_path[i];
    for(;path != nullptr;i++, path=library_search_path[i]) {
        auto apath = std::filesystem::absolute(path);
        if(!std::filesystem::is_directory(apath))
            continue;

        std::filesystem::directory_iterator diter(apath, std::filesystem::directory_options::skip_permission_denied);
        for(;diter != std::filesystem::end(diter); diter++) {
            auto ff = *diter;
            auto lpath = std::string(ff.path().filename());
            if((ff.is_regular_file() || ff.is_symlink()) && 
                    lpath.size() >= strlen(LIBNAME) && 
                    lpath.substr(0, strlen(LIBNAME)) == LIBNAME) {
                std::error_code error;
                global_options.libccat_path = std::filesystem::canonical(ff.path(), error);
                assert(!error && "what ???");
                std::cout << "found libccat.so at \"" << global_options.libccat_path << "\"" << std::endl;
                return;
            }
        }
    }

    std::cerr << "can't find libccat.so" << std::endl;
    exit(3);
} //}

/** exit status 
 * 0: success 
 * 1: exec fail
 * 2: bad option 
 * 3: can't find library 
 * 4: fail to write output */
int main(int argc, const char* const argv[]) //{
{
    parse_argv(argv);
    search_ccat();

    Server server(0);
    gserver = &server;
    signal(SIGINT, int_handle);

    server.listen();
    if(server.error()) {
        auto err = server.GetErrors();
        while(!err.empty()) {
            std::cout << err.top() << std::endl;
            err.pop();
        }
        return 1;
    }
    listening_path = server.GetPath();
    listening_port = ntohs(server.GetPort());

    pid_t cpid = 0;
    if((cpid = fork()) < 0) {
        std::cout << "fork() fail" << std::endl;
        return 4;
    } else if (cpid == 0) {
        run_command();
        assert(false && "unreachable");
    }

    signal(SIGCHLD, chld_handle);
    child_pid = cpid;

    json first = json::object();

    first["function"] = "fork";
    first["ppid"] = 0;
    first["pid"]  = cpid;
    first["cmd"]  = global_options.cmd;
    json args__ = json::object();
    size_t i=0;
    for(auto& arg: global_options.argv) {
        args__[std::to_string(i)] = arg;
        i++;
    }
    first["args"] = args__;
    server.PushMsg(first);

    while(run__ && !server.error()) {
        server.run();
    }

    if(int_signal)
        kill(cpid, SIGINT); // or SIGKILL
    int status;
    waitpid(cpid, &status, 0);

    if(server.error()) {
        auto errs = server.GetErrors();
        while(!errs.empty()) {
            std::cout << "error: " << errs.top() << std::endl;
            errs.pop();
        }
    }

    auto warns = server.GetWarns();
    while(!warns.empty()) {
        std::cout << "warn: " << warns.top() << std::endl;
        warns.pop();
    }

    auto json_data = server.GetData();
    auto data = json_data.dump(4);
    if(global_options.output_file.size() > 0) {
        std::fstream outfile(global_options.output_file, std::fstream::out);
        if(!outfile.is_open()) {
            std::cerr << "fail to open file '" << global_options.output_file << "'" << std::endl;
            exit(4);
        } else {
            outfile.write(data.c_str(), data.size());
            if(outfile.fail()) {
                std::cerr << "fail to write contents to file '" << global_options.output_file << "'" << std::endl;
                exit(4);
            }
        }
    } else {
        if(!global_options.suppress)
            std::cout << data << std::endl;
    }

    return 0;
} //}

