#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <assert.h>
#include <string.h>

#include <memory>
#include <iostream>
#include <atomic>

#include "server.h"

#define MAX_TCP_QUEUE 100
#define BUFSIZE       (0xffff + 2)


Server::Server(uint32_t addr, uint16_t port): m_addr(addr), m_port(port), m_mutex(), m_error_list() //{
{
    this->critical.m_procs = ProcessTree();
    this->critical.m_destroy = false;
    this->critical.m_first_thread_num = 0;
    this->m_run = true;

    this->m_error = false;
    this->m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(this->m_socket < 0) {
        this->new_error("Server: create socket fail");
        return;
    }
} //}

void Server::listen() //{
{
    assert(!this->error());
    if(this->m_run == false) return this->accept_new_connection();

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = this->m_addr;
    addr.sin_port = this->m_port;

    if(bind(this->m_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
        this->new_error("Server: bind socket fail");
        return;
    }

    if(::listen(this->m_socket, MAX_TCP_QUEUE) < 0) {
        this->new_error("Server: listen fail");
        return;
    }

    sockaddr_storage s_addr;
    uint32_t len = sizeof(s_addr);
    if(getsockname(this->m_socket, (sockaddr*)&s_addr, &len) < 0 || 
            s_addr.ss_family != AF_INET) {
        this->new_error("Server: get addr:port fail");
        return;
    }
    this->m_addr = ((sockaddr_in*)&s_addr)->sin_addr.s_addr;
    this->m_port = ((sockaddr_in*)&s_addr)->sin_port;
} //}
void Server::run() //{
{
    assert(!this->error());
    this->accept_new_connection();
} //}

/** [static] */
void Server::handle_new_connection(Server* _this, int fd, int tid) //{
{
    assert(fd > 0);
    char maxbuf[BUFSIZE];
    int pos = 0;

    while(_this->m_run) {
        errno = 0;
        int len = recv(fd, maxbuf + pos, sizeof(maxbuf) - pos, MSG_DONTWAIT);
        if(len <= 0) {
            if(errno == EAGAIN)
                std::this_thread::yield();
            else
                break;
        } else {
            pos += len;
            if(pos < 2) continue;
            uint16_t msg_len = ntohs(*(uint16_t*)maxbuf);
            if(pos < msg_len + 2) continue;
            _this->new_message(maxbuf + 2, pos - 1);
            pos = pos - (msg_len + 2);
        }
    }

    shutdown(fd, 0);
    _this->thread_finish(tid);
    return;
} //}
void Server::accept_new_connection() //{
{
    this->m_run = true;
    sockaddr_storage o_addr;
    uint32_t o_len = sizeof(o_addr);
    int new_socket;
    while(this->m_run) {
        if((new_socket = accept(this->m_socket, (sockaddr*)&o_addr, &o_len)) <= 0) {
            continue;
        }

        this->lock();
        auto tid = this->critical.m_first_thread_num++;
        this->critical.m_threads[tid] = new std::thread(handle_new_connection, this, new_socket, tid);
        this->unlock();

        this->clean_threads();
    }
} //}

/** 
 * {
 *     "function": <fork | exec>,
 *     "pid": <int>,
 *     "ppid": <int>,
 *     "cmd": string,
 *     "args": string[]
 * }
 */
struct __mutex_unlocker {
    std::mutex& m_mutex;
    inline __mutex_unlocker(std::mutex& mutex): m_mutex(mutex) {}
    inline ~__mutex_unlocker() {m_mutex.unlock();}
};
bool Server::new_message_without_lock(const char* buf, size_t len, bool postpone) //{
{
    json msg;
    try {
        msg = json::parse(std::string(buf, buf + len));
    } catch (json::exception err) {
        return new_warn_without_lock("Server: bad json, parse error: " + 
                std::string(err.what()) + " in " + 
                std::string(buf, buf+len));
    }
    if(!msg.is_object() || 
       !msg["function"].is_string() ||
       !msg["pid"].is_number_integer()) 
        return new_warn_without_lock("Server: bad json, unexpected");

    std::string func = msg["function"].get<std::string>();
    int pid = msg["pid"].get<int>();
    if(pid <= 0) return new_warn_without_lock("Server: bad json, pid field loss");
    if(func == "fork") {
        if(this->critical.m_pidmap.size() == 0) {
            if(!msg["cmd"].is_string())
                return new_warn_without_lock("Server: first fork message need cmd");
            if(!msg["args"].is_object())
                return new_warn_without_lock("Server: first fork message need args");

            std::vector<std::string> argv;
            std::map<int, std::string> __argv;

            for(auto iter = msg["args"].begin();iter!=msg["args"].end();iter++) {
                std::string k = iter.key();
                if(!iter.value().is_string()) {
                    new_warn_without_lock("Server: bad cmd args, need string");
                    continue;
                }
                std::string v = iter.value().get<std::string>();
                int kk = atoi(k.c_str());
                __argv[kk] = v;
            }
            for(auto& kv: __argv) argv.push_back(kv.second);

            this->critical.m_procs = ProcessTree(0, msg["pid"].get<int>(), msg["cmd"].get<std::string>(), argv);
            this->critical.m_pidmap[pid] = &this->critical.m_procs;
            return true;
        }

        if(!msg["ppid"].is_number_integer()) return new_warn_without_lock("Server: bad json, ppid field loss");
        int ppid = msg["ppid"].get<int>();
        if(ppid <= 0) return new_warn_without_lock("Server: bad json, ppid should be positive");

        if(this->critical.m_pidmap.find(ppid) == this->critical.m_pidmap.end()) {
            if(postpone) {
                this->postpone_msg(ppid, buf, len);
                return false;
            } else {
                return this->new_warn_without_lock("Server: unexpected ppid " + std::to_string(ppid));
            }
        }

        auto pp = this->critical.m_pidmap[ppid];
        json new_proc = json::object();
        this->critical.m_pidmap[pid] = pp->fork_this(pid);
        this->handle_postponed_msg(pid);
    } else if(func == "exec") {
        if(!msg["cmd"].is_string()) return new_warn_without_lock("Server: bad json, cmd field loss");
        if(!msg["args"].is_object()) return new_warn_without_lock("Server: bad json, args field loss");
        std::string cmd = msg["cmd"].get<std::string>();

        if(this->critical.m_pidmap.find(pid) == this->critical.m_pidmap.end()) {
            if(postpone) {
                this->postpone_msg(pid, buf, len);
                return false;
            } else {
                return this->new_warn_without_lock("Server: unexpected ppid " + std::to_string(pid));
            }
        }

        std::vector<std::string> argv;
        std::map<int, std::string> __argv;

        for(auto iter = msg["args"].begin();iter!=msg["args"].end();iter++) {
            std::string k = iter.key();
            if(!iter.value().is_string()) {
                new_warn_without_lock("Server: bad cmd args, need string");
                continue;
            }
            std::string v = iter.value().get<std::string>();
            int kk = atoi(k.c_str());
            __argv[kk] = v;
        }
        for(auto& kv: __argv) argv.push_back(kv.second);

        auto pp = this->critical.m_pidmap[pid];
        pp->exec_with(msg["cmd"].get<std::string>(), argv);
    } else {
        return new_warn_without_lock("Server: unexpected function");
    }

    return true;
} //}
bool Server::new_message(const char* buf, size_t len) //{
{
    this->lock();
    auto unlocker = std::make_shared<__mutex_unlocker>(this->m_mutex);

    return this->new_message_without_lock(buf, len, true);
} //}

void Server::postpone_msg(pid_t pid, const char* buf, size_t len) //{
{
    if(this->m_postponed_msg.find(pid) == this->m_postponed_msg.end())
        this->m_postponed_msg[pid] = std::set<std::string>();
    this->m_postponed_msg[pid].insert(std::string(buf, buf + len));
} //}
void Server::handle_postponed_msg(pid_t new_pid) //{
{
    if(this->m_postponed_msg.find(new_pid) == this->m_postponed_msg.end()) return;
    auto& theset = this->m_postponed_msg[new_pid];

    for(auto& msg: theset)
        this->new_message_without_lock(msg.c_str(), msg.size(), false);

    this->m_postponed_msg.erase(this->m_postponed_msg.find(new_pid));
} //}

bool Server::PushMsg(const json& jjj) //{
{
    std::string buf = jjj.dump(4);
    return this->new_message(buf.c_str(), buf.size());
} //}

/** [static] */
void Server::connect_to(Server* _this, uint32_t addr, uint16_t port, int tid) //{
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0) goto FAIL;

    sockaddr_in in_addr;
    in_addr.sin_family = AF_INET;
    in_addr.sin_addr.s_addr = addr;
    in_addr.sin_port = port;
    if(connect(sock, (sockaddr*)&in_addr, sizeof(in_addr)) < 0)
        goto FAIL; 

    shutdown(sock, 0);
    _this->thread_finish(tid);
    return;

FAIL:
    fprintf(stderr, "can't stop the server, just exit\n");
    exit(1);
} //}

#ifdef __BIG_ENDIAN__
#define DEFAULT_ADDR (0x7f000001)
#else
#define DEFAULT_ADDR (0x0100007f)
#endif
void Server::stop() //{
{
    this->m_run = false;

    this->lock();
    auto tid = this->critical.m_first_thread_num++;
    this->critical.m_threads[tid]= new std::thread(connect_to, this, 
            this->m_addr != 0 ? this->m_addr : DEFAULT_ADDR, this->m_port, tid);
    this->unlock();
} //}

void Server::lock()   {this->m_mutex.lock();}
void Server::unlock() {this->m_mutex.unlock();}

json     Server::GetData() //{
{
    this->lock();
    json data = this->critical.m_procs;
    this->unlock();
    return data;
} //}
uint16_t Server::GetPort() //{
{
    return this->m_port;
} //}

bool Server::error() {return this->m_error;}

bool Server::new_error(const std::string& err) //{
{
    this->m_error = true;
    this->m_error_list.push(err);
    return false;
} //}
bool Server::new_warn_without_lock(const std::string& warn) //{
{
    this->critical.m_warn_list.push(warn);
    return false;
} //}
bool Server::new_warn(const std::string& warn) //{
{
    this->lock();
    this->new_warn_without_lock(warn);
    this->unlock();
    return false;
} //}

std::stack<std::string> Server::GetErrors() //{
{
    return this->m_error_list;
} //}
std::stack<std::string> Server::GetWarns() //{
{
    this->lock();
    auto ans = this->critical.m_warn_list;
    if(this->m_postponed_msg.size() > 0)
        ans.push("Server: unhandled message " + std::to_string(this->m_postponed_msg.size()));
    this->unlock();
    return ans;
} //}

void Server::thread_finish(int tid) //{
{
    this->lock();
    if(this->critical.m_destroy) {
        this->unlock();
        return;
    }
    assert(this->critical.m_threads.find(tid) != this->critical.m_threads.end());
    this->critical.m_finished.insert(this->critical.m_threads[tid]);
    this->critical.m_threads.erase(this->critical.m_threads.find(tid));
    this->unlock();
} //}

void Server::clean_threads() //{
{
    this->lock();
    auto the_copy = this->critical.m_finished;
    for(auto& t: the_copy) {
        if(t->joinable()) t->join(); // The threads in m_finished is impossible to regain a lock
        delete t;
        this->critical.m_finished.erase(this->critical.m_finished.find(t));
    }
    this->unlock();
} //}
Server::~Server() //{
{
    this->lock();
    this->critical.m_destroy = true;
    auto copy = this->critical.m_threads;
    this->unlock();

    for(auto& t: copy) {
        if(t.second->joinable()) t.second->join();
        delete t.second;
    }

    clean_threads();
} //}



static int the_sup_uid = 0;
ProcessTree::ProcessTree() //{
{
    this->m_cmd = "";
    this->m_ppid = 0;
    this->m_pid = 0;

    this->uid = the_sup_uid++;
} //}
ProcessTree::ProcessTree(pid_t ppid, pid_t pid, std::string cmd, std::vector<std::string> argv) //{
{
    this->m_cmd = cmd;
    this->m_ppid = ppid;
    this->m_pid = pid;
    this->m_args = argv;

    this->uid = the_sup_uid++;
} //}

void         ProcessTree::exec_with(std::string cmd, std::vector<std::string> argv) //{
{
    this->m_exec_history.push_back(std::make_pair(std::move(this->m_cmd), std::move(this->m_args)));
    this->m_cmd = cmd;
    this->m_args = argv;
} //}
ProcessTree* ProcessTree::fork_this(pid_t new_pid) //{
{
    ProcessTree* the_child = new ProcessTree();
    the_child->m_pid = new_pid;
    the_child->m_ppid = this->m_pid;
    the_child->m_cmd = this->m_cmd;
    the_child->m_args = this->m_args;
    this->m_children.push_back(the_child);

    return the_child;
} //}

ProcessTree::operator json() //{
{
    json the_json = json::object();
    the_json["pid"]    = this->m_pid;
    the_json["ppid"]   = this->m_ppid;
    the_json["cmd"]    = this->m_cmd;
    the_json["nchild"] = this->m_children.size();
    the_json["uid"]    = this->uid;

    json the_args = json::object();
    int i = 0;
    for(auto& arg: this->m_args) {
        the_args[std::to_string(i)] = arg;
        i++;
    }
    the_json["args"]   = the_args;

    json children_json = json::array();
    for(auto child: this->m_children)
        children_json.push_back(json(*child));
    the_json["children"] = children_json;

    return the_json;
} //}

ProcessTree::~ProcessTree() //{
{
    for(auto child: this->m_children) delete child;
} //}

