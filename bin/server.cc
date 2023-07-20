#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <assert.h>
#include <string.h>
#include <time.h>

#include <memory>
#include <iostream>
#include <atomic>
#include <random>

#include "server.h"
#include "../lib/cmdcat.h"

#include <fcntl.h>

#define MAX_TCP_QUEUE 100
#define BUFSIZE       MAX_MESSAGE_SIZE

static char __socket_name[sizeof(struct sockaddr_un) + 1] = {0};
static std::default_random_engine engine;
static const char* random_unix_socket_name() //{
{
    time_t t; time(&t);
    engine.seed(t);
    std::uniform_int_distribution<char> dist('a', 'z');
    char tmp[] = "/tmp/socket-";
    strcpy(__socket_name, tmp);
    size_t i=0;
    for(i=sizeof(tmp)-1;i<sizeof(tmp) + 20;i++) {
        char c = dist(engine);
        __socket_name[i] = c;
    }
    __socket_name[i] = 0;
    return __socket_name;
} //}


Server::Server(bool unix_domain, bool datagram, uint16_t port): m_addr(0), m_port(port), m_mutex(), m_error_list() //{
{
    this->critical.m_procs = ProcessTree();
    this->critical.m_destroy = false;
    this->critical.m_first_thread_num = 0;
    this->m_run = true;

    this->m_error  = false;
    this->m_socket = 0;

    this->m_unix_domain = unix_domain;
    this->m_datagram = datagram;

    memset(this->m_socket_pathname, 0, sizeof(this->m_socket_pathname));
} //}

void Server::build_this_socket_and_sockaddr() //{
{
    assert(this->m_socket <= 0);

    struct sockaddr_storage addr;
    if(!this->m_unix_domain) {
        if(this->m_datagram)
            this->m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        else
            this->m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(&addr);
        addr_in->sin_family = AF_INET;
        addr_in->sin_addr.s_addr = this->m_addr;
        addr_in->sin_port   = this->m_port;
        if(this->m_socket > 0) {
            if(bind(this->m_socket, reinterpret_cast<struct sockaddr*>(addr_in), sizeof(*addr_in)) < 0) {
                close(this->m_socket);
                this->m_socket = 0;
            } else {
                socklen_t sl = sizeof(addr);
                if(getsockname(this->m_socket, reinterpret_cast<struct sockaddr*>(&addr), &sl) < 0 || addr.ss_family != AF_INET) {
                    close(this->m_socket);
                    this->m_socket = 0;
                } else {
                    this->m_port = addr_in->sin_port;
                    this->m_addr = addr_in->sin_addr.s_addr;
                }
            }
        }
    } else {
        if(this->m_datagram)
            this->m_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
        else
            this->m_socket = socket(AF_UNIX, SOCK_STREAM, 0);

        if(this->m_socket > 0) {
            struct sockaddr_un* addr_un = reinterpret_cast<struct sockaddr_un*>(&addr);
            if(strlen(this->m_socket_pathname) == 0)
                strcpy(this->m_socket_pathname, random_unix_socket_name());
            addr_un->sun_family = AF_UNIX;
            strcpy(addr_un->sun_path, this->m_socket_pathname);

            int redoable = 1;
REBIND:
            if(bind(this->m_socket, reinterpret_cast<struct sockaddr*>(addr_un), sizeof(*addr_un)) < 0) {
                if(errno == EADDRINUSE && redoable) {
                    redoable = 0;
                    unlink(addr_un->sun_path);
                    goto REBIND;
                } else {
                    close(this->m_socket);
                    this->m_socket = 0;
                }
            }
        }
    }

    if(this->m_socket <= 0)
        this->new_error("Server: socket error");
} //}
void Server::listen() //{
{
    assert(!this->error());
    this->build_this_socket_and_sockaddr();
    if(this->m_socket <= 0) return;
    if(this->m_datagram) return;

    if(::listen(this->m_socket, MAX_TCP_QUEUE) < 0) {
        close(this->m_socket);
        this->m_socket = 0;
        this->new_error("Server: listen fail");
        return;
    }
}
 //}

void Server::run() //{
{
    assert(!this->error());
    if(this->m_datagram)
        this->poll_socket();
    else
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
            while(true) {
                pos += len;
                if(pos < 2) break;
                uint16_t msg_len = ntohs(*(uint16_t*)maxbuf);
                if(pos < msg_len + 2) break;

                _this->new_message(maxbuf + 2, msg_len);
                if(pos > msg_len + 2) {
                    memmove(maxbuf, maxbuf + 2 + msg_len, pos - msg_len - 2);
                    pos = pos - msg_len - 2;
                } else pos = 0;
                len = 0;
            }
        }
    }

    shutdown(fd, SHUT_RDWR);
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
        if((new_socket = accept(this->m_socket, reinterpret_cast<sockaddr*>(&o_addr), &o_len)) <= 0) {
            continue;
        }

        this->lock();
        auto tid = this->critical.m_first_thread_num++;
        this->critical.m_threads[tid] = new std::thread(handle_new_connection, this, new_socket, tid);
        this->unlock();

        this->clean_threads();
    }
} //}

void Server::poll_socket() //{
{
    int fd = this->m_socket;
    assert(fd > 0);
    assert(this->m_datagram);
    char maxbuf[BUFSIZE];

    while(this->m_run) {
        errno = 0;
        int len = recvfrom(fd, maxbuf, sizeof(maxbuf), 0, nullptr, nullptr);
        if(len <= 0) {
            int error = 0;
            socklen_t l = sizeof(error);
            int r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &l);
            if(r != 0 || error != 0 || l == 0) {
                close(fd);
                this->m_socket = 0;
                this->new_error("read socket fail");
                return;
            }
        } else {
            if(len > 10)
                this->new_message(maxbuf, len);
        }
    }

    close(fd);
    return;
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
    inline explicit __mutex_unlocker(std::mutex& mutex): m_mutex(mutex) {}
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

        std::map<std::string, std::string> envs;
        std::string cwd;
        if(msg["cwd"].is_string()) cwd = msg["cwd"].get<std::string>();
        if(msg["envs"].is_array()) {
            for(auto& v: msg["envs"]) {
                if(!v.is_string()) continue;
                std::string kv = v.get<std::string>();
                size_t i=0;
                for(;i<kv.size();i++)
                    if(kv[i] == '=') break;
                if(i == 0) continue;
                std::string nv = "";
                if(kv.size() > (i + 1)) nv = kv.substr(i + 1);
                envs[kv.substr(0, i)] = nv;
            }
        }

        auto pp = this->critical.m_pidmap[pid];
        pp->exec_with(msg["cmd"].get<std::string>(), std::move(cwd), std::move(argv), std::move(envs));
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
void Server::connect_to(Server* _this, int tid) //{
{
    assert(_this->m_socket > 0);

    struct sockaddr_storage addr;
    socklen_t sl = 0;
    int sock = socket(_this->m_unix_domain ? AF_UNIX : AF_INET, _this->m_datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
    if(sock <= 0) goto FAIL;

    if(_this->m_unix_domain) {
        struct sockaddr_un* addr_un = reinterpret_cast<struct sockaddr_un*>(&addr);
        addr_un->sun_family = AF_UNIX;
        strcpy(addr_un->sun_path, _this->m_socket_pathname);
        sl = sizeof(*addr_un);
    } else {
        struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(&addr);
        addr_in->sin_family = AF_INET;
        addr_in->sin_addr.s_addr = _this->m_addr;
        addr_in->sin_port = _this->m_port;
        sl = sizeof(*addr_in);
    }

    if(_this->m_datagram) {
        char buf[] = "exit";
        if(sendto(sock, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr*>(&addr), sl) < 0) goto FAIL;
    } else {
        if(connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sl) < 0) goto FAIL;
    }

    close(sock);
    _this->thread_finish(tid);
    return;
FAIL:
    if(errno != 0)
        fprintf(stderr, "error: %s\n", strerror(errno));
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
    assert(this->m_run == true);
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // FIXME
    this->m_run = false;

    this->lock();
    auto tid = this->critical.m_first_thread_num++;
    this->critical.m_threads[tid]= new std::thread(connect_to, this, tid);
    this->unlock();
} //}

void Server::lock()   {this->m_mutex.lock();}
void Server::unlock() {this->m_mutex.unlock();}

json        Server::GetData() //{
{
    this->lock();
    json data(this->critical.m_procs);
    this->unlock();
    return data;
} //}
uint16_t    Server::GetPort() //{
{
    return this->m_port;
} //}
std::string Server::GetPath() //{
{
    return this->m_socket_pathname;
} //}
int Server::GetSocketDomain()  {return this->m_unix_domain ? AF_UNIX : AF_INET;}
int Server::GetSocketType()    {return this->m_datagram    ? SOCK_DGRAM : SOCK_STREAM;}
ProcessTree* Server::GetProc() {return &this->critical.m_procs;}

bool Server::error() {return this->m_error;}

bool Server::new_error(const std::string& err) //{
{
    this->m_error = true;
    if(errno != 0) {
        this->m_error_list.push(err + ": " + std::string(strerror(errno)));
    } else {
        this->m_error_list.push(err);
    }
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
    if(this->m_postponed_msg.size() > 0) {
        ans.push("Server: unhandled message " + std::to_string(this->m_postponed_msg.size()));
        for(auto& unh: this->m_postponed_msg) {
            for(auto& un: unh.second) {
                std::cout << un << std::endl;
            }
        }
    }
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

void         ProcessTree::exec_with(std::string cmd, std::string cwd, 
                                    std::vector<std::string> argv, 
                                    std::map<std::string, std::string> envs) //{
{
    this->m_exec_history.push_back(std::make_pair(std::move(this->m_cmd), std::move(this->m_args)));
    this->m_cmd = cmd;
    this->m_cwd = cwd;
    this->m_args = argv;
    this->m_envs = envs;
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

ProcessTree::operator json() const //{
{
    json the_json = json::object();
    the_json["pid"]    = this->m_pid;
    the_json["ppid"]   = this->m_ppid;
    the_json["cmd"]    = this->m_cmd;
    the_json["cwd"]    = this->m_cwd;
    the_json["nchild"] = this->m_children.size();
    the_json["uid"]    = this->uid;

    json the_args = json::object();
    int i = 0;
    for(auto& arg: this->m_args) {
        the_args[std::to_string(i)] = arg;
        i++;
    }
    the_json["args"]   = the_args;

    json the_envs = json::object();
    for(auto& env: this->m_envs)
        the_envs[env.first] = env.second;
    the_json["envs"] = the_envs;

    json children_json = json::array();
    for(auto child: this->m_children)
        children_json.push_back(json(*child));
    the_json["children"] = children_json;

    json the_history = json::object();
    size_t hi = 0;
    for(auto& his: this->m_exec_history) {
        json h = json::object();
        h["cmd"] = his.first;

        json v = json::object();
        size_t i=0;
        for(auto& a: his.second)
            v[std::to_string(i++)] = a;
        h["argv"] = v;

        the_history[std::to_string(hi++)] = h;
    }
    the_json["history"] = the_history;

    return the_json;
} //}

ProcessTree::~ProcessTree() //{
{
    for(auto child: this->m_children) delete child;
} //}

