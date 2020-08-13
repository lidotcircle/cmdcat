#include "server.h"
#include "plugin.h"

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
using namespace std;

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
    string output_file;
    string libccat_path;

    bool suppress = false;
    bool unix_domain_socket = true;
    bool datagram_socket = true;
    string plugin = "raw";
    map<string, string> plugin_argv;

    string              cmd;
    vector<string> argv;
} global_options;

static uint32_t listening_port;
static string   listening_path;
static int      socket_domain;
static int      socket_type;
static pid_t    child_pid;


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
        cout << string(env) << endl;
} //}

static void setup_environment_variables() //{
{
    assert(socket_domain == AF_INET || socket_domain == AF_UNIX);
    assert(socket_type   == SOCK_STREAM || socket_type == SOCK_DGRAM);

    setenv(SERVER_PORT_ENVNAME, to_string(listening_port).c_str(), 1);
    setenv(SERVER_PATH_ENVNAME, listening_path.c_str(), 1);
    if(socket_domain == AF_INET)
        setenv(SERVER_DOMAIN_ENVNAME, "AF_INET", 1);
    else
        setenv(SERVER_DOMAIN_ENVNAME, "AF_UNIX", 1);

    if(socket_type == SOCK_STREAM)
        setenv(SERVER_TYPE_ENVNAME, "SOCK_STREAM", 1);
    else
        setenv(SERVER_TYPE_ENVNAME, "SOCK_DGRAM", 1);

    setenv(ENV_PRELOAD, global_options.libccat_path.c_str(), 1);
    // TODO APPLE

} //}
static char* const* get_argv(const vector<string>& argv) //{
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
static void empty_handle(int) {cout << "empty handler" << endl;}
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
        cerr << "sigwait() fail" << endl;
        exit(1);
    }
    */
    this_thread::sleep_for(chrono::milliseconds(500));

    assert(global_options.cmd.size() > 0);
    setup_environment_variables();

    auto argv = get_argv(global_options.argv);
    if(execvpe(global_options.cmd.c_str(), argv, environ) < 0) {
        cerr << "run \"";
        cerr << global_options.cmd;
        for(auto& arg: global_options.argv)
            cerr << " " << arg;
        cerr << "\"fail" << endl;
        exit(1);
    }
    assert(false && "unreachable");
} //}

static pair<string, string> equal_pair(const string& kv) //{
{
    string k=kv,v;
    int i = 0;
    for(;i<kv.size();i++) {
        if(kv[i] == '=') {
            k = kv.substr(0, i);
            if(i+1<kv.size())
                v = kv.substr(i+1);
        }
    }
    return make_pair(k,v);
} //}
static void usage() //{
{
    auto usage = 
        "Usage: \n"
        "       cmdcat [-solih] <command>\n"
        "\n"
        "        -s                                   suppress stdout output\n"
        "        -o, --output        <file>           specify output file, default stdout\n"
        "        -l, --library       <file>           path of libccat\n"
        "        -i, --inet                           using AF_INET instead of AF_UNIX\n"
        "            --stream                         using SOCK_STREAM instead of SOCK_DGRAM\n"
        "        -p, --plugin        <plugin>         transform output by plugin\n"
        "            --list-plugin                    list available plugin\n"
        "        -h                                   display help\n";
    cout << usage;
} //}
static const map<char, bool> short_options = {
    {'o', true},
    {'l', true},
    {'s', false},
    {'i', false},
    {'p', true},
    {'h', false},
};
static const map<string, bool> long_options = {
    {"output",      true},
    {"library",     true},
    {"inet",        false},
    {"stream",      false},
    {"plugin",      true},
    {"list-plugin", false},
    {"help",        false}
};
static void handle_option(const string& option, const string& arg) //{
{
    if(option == "o" || option == "output") {
        if(global_options.output_file.size() > 0) {
            usage();
            cerr << "\nduplicated \"-o\" option" << endl;
            exit(2);
        } else {
            global_options.output_file = arg;
        }
    } else if (option == "l" || option == "library") {
        if(global_options.libccat_path.size() > 0) {
            usage();
            cerr << "\nduplicated \"-l\" option" << endl;
            exit(2);
        } else {
            global_options.libccat_path = arg;
        }
    } else if (option == "s") {
        global_options.suppress = true;
    } else if (option == "h" || option == "help") {
        usage();
        exit(0);
    } else if (option == "i" || option == "inet") {
        global_options.unix_domain_socket = false;
    } else if (option == "stream") {
        global_options.datagram_socket = false;
    } else if (option == "p" || option == "plugin") {
        int i = 0, j = 0;
        global_options.plugin_argv.clear();
        for(;j<arg.size();j++) {
            if(arg[j] == ',') {
                if(j == 0) {
                    usage();
                    exit(2);
                }
                if(i == 0) {
                    global_options.plugin = string(arg.c_str() + i, arg.c_str() + j);
                } else {
                    string kv = string(arg.c_str() + i, arg.c_str() + j);
                    auto k_v = equal_pair(kv);
                    global_options.plugin_argv.insert(k_v);
                }
                i = ++j;
            }
        }
        if(i == 0)
            global_options.plugin = arg;
        else if(i < arg.size())
            global_options.plugin_argv.insert(equal_pair(arg.substr(i)));

        if(c_plugin.find(global_options.plugin) == c_plugin.end()) {
            usage();
            cerr << "unknown plugin '" << global_options.plugin << "'" << endl;
            exit(2);
        }
    } else if (option == "list-plugin") {
        if(c_plugin.size() == 0) {
            cerr << "no plugin avaliable" << endl;
            exit(2);
        }
        size_t maxl = 0;
        for(auto& p: c_plugin)
            if(p.first.size() > maxl) maxl = p.first.size();

        maxl += 8;
        for(auto& p: c_plugin)
            std::cout << "* " << p.first << string(maxl - p.first.size(), ' ') << p.second.second << std::endl;
        exit(0);
    } else {
        cerr << "unimplement option '" << option << endl;
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
                        cerr << "\nunknown option " << string(arg) << endl;
                        exit(2);
                    } else {
                        string option(1, c);
                        string opt_arg = "";
                        const bool has_arg = short_options.find(c)->second;
                        if(has_arg) {
                            if(++j != len || (arg = argv[++i]) == nullptr) {
                                usage();
                                cerr << "\noption '-" << string(1, c) << "' require argument" << endl;
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
                    cerr << "\nunknown option " << string(arg) << endl;
                    exit(2);
                }
                string option  = string(arg + 2);
                string opt_arg = "";
                const bool has_arg = long_options.find(string(arg+2))->second;
                if(has_arg) {
                    if((arg = argv[++i]) == nullptr) {
                        usage();
                        cerr << "\noption '" << string(arg) << "' require augument" << endl;
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
        cerr << "command must be specified" << endl;
        exit(2);
    }

    global_options.cmd = string(arg);
    for(;arg!=nullptr;++i, arg=argv[i])
        global_options.argv.push_back(string(arg));
} //}

#define LIBNAME "libccat.so"
static void search_ccat() //{
{
    if(global_options.libccat_path.size() > 0) {
        if(!filesystem::is_regular_file(global_options.libccat_path) &&
           !filesystem::is_symlink(global_options.libccat_path)) {
            cerr << "file \"" << global_options.libccat_path << "\" doesn't exist" << endl;
            exit(3);
        }
        error_code error;
        global_options.libccat_path = filesystem::canonical(global_options.libccat_path, error);
        assert(!error && "path ... ???");
        return;
    }

    size_t i=0;
    const char* path = library_search_path[i];
    for(;path != nullptr;i++, path=library_search_path[i]) {
        auto apath = filesystem::absolute(path);
        if(!filesystem::is_directory(apath))
            continue;

        filesystem::directory_iterator diter(apath, filesystem::directory_options::skip_permission_denied);
        for(;diter != filesystem::end(diter); diter++) {
            auto ff = *diter;
            auto lpath = string(ff.path().filename());
            if((ff.is_regular_file() || ff.is_symlink()) && 
                    lpath.size() >= strlen(LIBNAME) && 
                    lpath.substr(0, strlen(LIBNAME)) == LIBNAME) {
                error_code error;
                global_options.libccat_path = filesystem::canonical(ff.path(), error);
                assert(!error && "what ???");
                // cout << "found libccat.so at \"" << global_options.libccat_path << "\"" << endl;
                return;
            }
        }
    }

    cerr << "can't find libccat.so" << endl;
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
    setup_c_plugins();
    parse_argv(argv);
    search_ccat();

    Server server(global_options.unix_domain_socket, global_options.datagram_socket);
    gserver = &server;
    signal(SIGINT, int_handle);

    server.listen();
    if(server.error()) {
        auto err = server.GetErrors();
        while(!err.empty()) {
            cout << err.top() << endl;
            err.pop();
        }
        return 1;
    }
    listening_path = server.GetPath();
    listening_port = ntohs(server.GetPort());
    socket_domain  = server.GetSocketDomain();
    socket_type    = server.GetSocketType();

    pid_t cpid = 0;
    if((cpid = fork()) < 0) {
        cout << "fork() fail" << endl;
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
        args__[to_string(i)] = arg;
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
            cout << "error: " << errs.top() << endl;
            errs.pop();
        }
    }

    auto warns = server.GetWarns();
    while(!warns.empty()) {
        cout << "warn: " << warns.top() << endl;
        warns.pop();
    }

    auto proc_tree = server.GetProc();
    assert(c_plugin.find(global_options.plugin) != c_plugin.end());
    string data = c_plugin[global_options.plugin].first(proc_tree, global_options.plugin_argv);

    if(global_options.output_file.size() > 0) {
        fstream outfile(global_options.output_file, fstream::out);
        if(!outfile.is_open()) {
            cerr << "fail to open file '" << global_options.output_file << "'" << endl;
            exit(4);
        } else {
            outfile.write(data.c_str(), data.size());
            if(outfile.fail()) {
                cerr << "fail to write contents to file '" << global_options.output_file << "'" << endl;
                exit(4);
            }
        }
    } else {
        if(!global_options.suppress)
            cout << data << endl;
    }

    return 0;
} //}

