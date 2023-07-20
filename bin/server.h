#pragma once


#include <vector>
#include <map>
#include <set>

#include <sys/un.h>

#include <nlohmann/json.hpp>
using namespace nlohmann;

#include <thread>
#include <mutex>
#include <stack>

class ProcessTree {
    public:
        pid_t m_ppid;
        pid_t m_pid;
        std::vector<ProcessTree*> m_children;
        std::string m_cmd;
        std::string m_cwd;
        std::vector<std::string> m_args;
        std::map<std::string, std::string> m_envs;

        size_t uid;

        std::vector<std::pair<std::string, std::vector<std::string>>> m_exec_history;


    public:
        ProcessTree();
        ProcessTree(pid_t ppid, pid_t pid, std::string cmd, std::vector<std::string> m_args);

        void         exec_with(std::string cmd, std::string cwd, 
                               std::vector<std::string> argv, std::map<std::string, std::string> envs);
        ProcessTree* fork_this(pid_t new_pid);

        explicit operator json() const;

        ~ProcessTree();
};

class Server {
    private:
        std::mutex m_mutex; // protect data in critical when multiple thread try to access
        bool m_run;         // whether continue listen new message

        int  m_socket;
        bool m_error;
        std::stack<std::string> m_error_list;

        uint32_t m_addr;
        uint16_t m_port;
        char     m_socket_pathname[sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path)];

        struct {
            ProcessTree m_procs;
            std::map<int, ProcessTree*> m_pidmap;

            std::map<int, std::thread*> m_threads;
            std::set<std::thread*> m_finished;
            int m_first_thread_num;

            bool m_destroy;
            std::stack<std::string> m_warn_list;
        } critical;
        std::map<pid_t, std::set<std::string>> m_postponed_msg;

        void lock();
        void unlock();

        void accept_new_connection();
        void poll_socket();

        static void connect_to(Server* _this, int tid);
        static void handle_new_connection(Server* _this, int fd, int tid);
        void thread_finish(int tid);
        bool new_message_without_lock(const char* buf, size_t len, bool postpone);
        bool new_message(const char* buf, size_t len);
        bool new_error(const std::string& error);
        bool new_warn_without_lock(const std::string& error);
        bool new_warn (const std::string& warn);

        void postpone_msg(pid_t pid, const char* buf, size_t len);
        void handle_postponed_msg(pid_t pid);
        void clean_threads();

        bool m_datagram;
        bool m_unix_domain;
        void build_this_socket_and_sockaddr();


    public:
        Server(bool unix_domain, bool datagram, uint16_t port = 0);
        Server() = delete;
        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;

        json         GetData();
        uint16_t     GetPort();
        std::string  GetPath();
        ProcessTree* GetProc();

        int GetSocketDomain();
        int GetSocketType();

        void listen();
        void run();
        void stop();
        bool error();

        bool PushMsg(const json&);

        std::stack<std::string> GetErrors();
        std::stack<std::string> GetWarns();

        ~Server();
};

