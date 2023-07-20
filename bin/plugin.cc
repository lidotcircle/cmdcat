#include "plugin.h"

#include <filesystem>
#include <iostream>

map<string, pair<ProcessTreeTransform, string>> c_plugin;
static void add_new_plugin(const string& name, ProcessTreeTransform func, const string& description) //{
{
    assert(c_plugin.find(name) == c_plugin.end());
    c_plugin[name] = make_pair(func, description);
} //}

static string raw_json(const ProcessTree* tree, const map<string, string>& kv) //{
{
    return json(*tree).dump(4);
} //}

struct compilation_database {
    string cmd;
    string cwd;
    string file;
    explicit operator json() const {
        json ret = json::object();
        ret["file"] = file;
        ret["command"] = cmd;
        ret["directory"] = cwd;
        return ret;
    }
};
static set<string> default_c_and_cpp = {
    "cc", "c++", "clang", "gcc", "g++"
};
static set<string> extension_c_and_cpp = {
    ".c", ".cc", ".cpp", ".cx", ".cxx"
};
static void __compilation_database_gen(const ProcessTree* tree, const map<string, string>& kv, vector<compilation_database>& out) //{
{
    string cmdname = filesystem::path(tree->m_cmd).filename();

    bool is = false;
    if(kv.find("compilers") == kv.end() || kv.find("add") != kv.end()) {
        is = default_c_and_cpp.find(cmdname) != default_c_and_cpp.end();
    } else {
        string compilers = kv.find("compilers")->second;
        set<string> new_compiler;
        int n=0,m=0;
        for(;n<compilers.size();n++) {
            if(compilers[n] == '.') {
                if(n > m && compilers.substr(m, n) == cmdname) {
                    is = true;
                    break;
                }
                m = ++n;
            }
        }
    }

    if(is) {
        string thecmd = tree->m_cmd;
        vector<string> c_files;
        for(auto& arg: tree->m_args) {
            thecmd += " "; thecmd += arg;
            if(extension_c_and_cpp.find(filesystem::path(arg).extension()) != extension_c_and_cpp.end()) {
                filesystem::path p = arg;
                if(p.is_relative()) {
                    error_code error;
                    p = filesystem::canonical(filesystem::path(tree->m_cwd).append(arg), error);
                    if(error) continue;
                }
                c_files.push_back(p);
            }
        }
        for(auto& f: c_files) {
            struct compilation_database m;
            m.cmd = thecmd;
            m.cwd = tree->m_cwd;
            m.file = f;
            out.push_back(m);
        }
    }

    for(auto& c: tree->m_children)
        __compilation_database_gen(c, kv, out);
} //}
static string compilation_database_json(const ProcessTree* tree, const map<string, string>& kv) //{
{
    vector<compilation_database> o;
    __compilation_database_gen(tree, kv, o);

    json array = json::array();
    for(auto& n: o)
        array.emplace_back(n);
    return array.dump(4);
} //}

void setup_c_plugins() //{
{
    add_new_plugin("raw", raw_json, "raw process tree with program execute arguments");
    add_new_plugin("compile-database", compilation_database_json, "compilation database to clang tool");
} //}

