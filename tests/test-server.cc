#include <nlohmann/json.hpp>
#include "server.h"

#include "../lib/cmdcat.h"

#include <signal.h>
#include <netdb.h>

#include <iostream>
#include <random>

#include <thread>
#include <chrono>
#include <set>
#include <map>

std::default_random_engine engine;

static Server* gserver;
static bool run__ = true;
static void int_handle(int sig) //{
{
    run__ = false;
    gserver->stop();
} //}

static char cmd_buf[30] = {0};
static const char* random_cmd() //{
{
    size_t len = (engine() % 20 + 5);
    std::uniform_int_distribution<char> dist('a', 'z');
    size_t i=0;
    for(i=0;i<len;i++)
        cmd_buf[i] = dist(engine);
    cmd_buf[i] = 0;
    return cmd_buf;
} //}

typedef char* __charptr;
static __charptr argv_buf[50] = {nullptr};
static char argv_buf_store[50][100];
static __charptr* random_argv() //{
{
    size_t len = engine() % 20;
    std::uniform_int_distribution<char> dist('a', 'z');
    size_t i=0;
    for(i=0;i<len;i++) {
        argv_buf[i] = argv_buf_store[i];
        size_t a_len = engine() % 20 + 2;
        size_t j=0;
        for(;j<a_len;j++)
            argv_buf[i][j] = dist(engine);
        argv_buf[i][j] = 0;
    }
    argv_buf[i] = nullptr;
    return argv_buf;
} //}

static std::set<int> used_pid;
static int new_pid() //{
{
    std::uniform_int_distribution<int> dist(0xfff, 0xffff);
    while(true) {
        int pid = dist(engine);
        if(used_pid.find(pid) != used_pid.end()) continue;
        used_pid.insert(pid);
        return pid;
    }
} //}
static int get_exist_pid() //{
{
    std::uniform_int_distribution<int> dist(0);
    int n = dist(engine) % used_pid.size();
    auto iter = used_pid.begin();
    for(int i=0;i<n;i++) iter++;
    return *(iter);
} //}

static void do_a_exec() //{
{
    pid_t pid        = get_exist_pid();
    const char*  cmd = random_cmd();
    char** argv      = random_argv();

    std::cout << "exec " << cmd << std::endl;

    send_exec(pid, cmd, argv, nullptr);
} //}
static void do_a_fork() //{
{
    pid_t ppid = get_exist_pid();
    pid_t pid  = new_pid();

    std::cout << "fork " << ppid << "to " << pid << std::endl;

    send_fork(ppid, pid, nullptr, nullptr, nullptr);
} //}
static void send_thread() //{
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
    used_pid.insert(100);
    send_fork(0, 100, "main", nullptr, nullptr);

    while(run__) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        bool fork = (engine() % 2 == 0);
        if(fork) do_a_fork();
        else     do_a_exec();
    }
} //}

int main() 
{
    Server server(0, htons(8080));
    gserver = &server;
    signal(SIGINT, int_handle);

    setenv("FORCE_AF_INET", "yes", 1);
    server.listen();
    std::cout << "listen at port: " << ntohs(server.GetPort()) << std::endl;
    setenv(SERVER_PORT_ENVNAME, std::to_string(ntohs(server.GetPort())).c_str(), 1);
    setenv(SERVER_PATH_ENVNAME, server.GetPath().c_str(), 1);

    auto thread = std::thread(send_thread);
    server.run();

    if(server.error()) {
        auto errs = server.GetErrors();
        while(!errs.empty()) {
            std::cout << errs.top() << std::endl;
            errs.pop();
        }
    }

    auto warns = server.GetWarns();
    while(!warns.empty()) {
        std::cout << warns.top() << std::endl;
        warns.pop();
    }

    auto data = server.GetData();
    // std::cout << data.dump(4) << std::endl;

    thread.join();
    return 0;
}


