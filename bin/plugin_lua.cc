#include "plugin_lua.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include <iostream>
#include <filesystem>
#include <vector>

static string lua_source;
static lua_State* state = nullptr;
static map<string,string> lua_plugins;

static bool initialized = false;
static pthread_mutex_t __mutex = PTHREAD_MUTEX_INITIALIZER;

map<string, string> list_lua_plugins() //{
{
    return lua_plugins;
} //}

bool setup_lua_plugins(const string& file) //{
{
    lua_source = file;
    if(luaL_dofile(state, lua_source.c_str()) != 0)
        return false;

    lua_pushglobaltable(state);
    lua_pushnil(state);
    while(lua_next(state, -2) != 0) {
        string key = lua_tostring(state, -2);
        if(lua_type(state, -1) == LUA_TFUNCTION && 
               key.size() > strlen(PLUGIN_PREFIX) &&
               key.substr(0, strlen(PLUGIN_PREFIX)) == PLUGIN_PREFIX) {
            string plugin = key.substr(strlen(PLUGIN_PREFIX));
            string desc_key = string(DESCRIPTION_PREFIEX) + plugin;
            string desc = "    ";
            if(lua_getglobal(state, desc_key.c_str()) == LUA_TSTRING)
                desc = lua_tostring(state, -1);
            lua_plugins[plugin] = desc;
            lua_pop(state, 1);
        }
        lua_pop(state, 1);
    }
    lua_pop(state, 1);

    return true;
} //}

static void set_the_table(ProcessTree* tree) //{
{
    lua_checkstack(state, 5);
    lua_newtable(state);

    lua_pushstring(state, "args");
    lua_newtable(state);
    for(size_t i=1; i<=tree->m_args.size();i++) {
        auto& arg = tree->m_args[i - 1];
        lua_pushnumber(state, i);
        lua_pushstring(state, arg.c_str());
        lua_settable(state, -3);
    }
    lua_settable(state, -3);

    lua_pushstring(state, "envs");
    lua_newtable(state);
    for(auto& kv: tree->m_envs) {
        lua_pushstring(state, kv.first.c_str());
        lua_pushstring(state, kv.second.c_str());
        lua_settable(state, -3);
    }
    lua_settable(state, -3);

    lua_pushstring(state, "cmd");
    lua_pushstring(state, tree->m_cmd.c_str());
    lua_settable(state, -3);

    lua_pushstring(state, "cwd");
    lua_pushstring(state, tree->m_cwd.c_str());
    lua_settable(state, -3);

    lua_pushstring(state, "pid");
    lua_pushnumber(state, tree->m_pid);
    lua_settable(state, -3);

    lua_pushstring(state, "ppid");
    lua_pushnumber(state, tree->m_ppid);
    lua_settable(state, -3);

    lua_pushstring(state, "historys");
    lua_newtable(state);
    for(size_t i=1;i<=tree->m_exec_history.size();i++) {
        auto& hist = tree->m_exec_history[i - 1];
        lua_pushnumber(state, i);
        lua_newtable(state);

        lua_pushstring(state, "cmd");
        lua_pushstring(state, hist.first.c_str());
        lua_settable(state, -3);

        lua_pushstring(state, "args");
        lua_newtable(state);
        for(size_t i=1; i<=tree->m_args.size();i++) {
            auto& arg = tree->m_args[i - 1];
            lua_pushnumber(state, i);
            lua_pushstring(state, arg.c_str());
            lua_settable(state, -3);
        }
        lua_settable(state, -3);

        lua_settable(state, -3);
    }
    lua_settable(state, -3);

    lua_pushstring(state, "children");
    lua_newtable(state);
    for(size_t i=1;i<=tree->m_children.size();i++) {
        auto& child = tree->m_children[i - 1];
        lua_pushnumber(state, i);
        set_the_table(child);
        lua_settable(state, -3);
    }
    lua_settable(state, -3);
} //}
string invoke_plugin(const string& plugin, const map<string,string>& kwargv, ProcessTree* data, bool& error) //{
{
    if(lua_plugins.find(plugin) == lua_plugins.end()) {
        error = true;
        return "";
    }

    string fname = string(PLUGIN_PREFIX) + plugin;
    auto f = lua_getglobal(state, fname.c_str());
    set_the_table(data);

    lua_newtable(state);
    for(auto& kv: kwargv) {
        lua_pushstring(state, kv.first.c_str());
        lua_pushstring(state, kv.second.c_str());
        lua_settable(state, -3);
    }

    assert(lua_type(state, -1) == LUA_TTABLE);
    assert(lua_type(state, -2) == LUA_TTABLE);
    assert(lua_type(state, -3) == LUA_TFUNCTION);
    lua_call(state, 2, 1);

    string ret = lua_tostring(state, -1);
    lua_pop(state, 1);

    error = false;
    return ret;
} //}

static void on_load() __attribute__((constructor));
static void on_unload() __attribute__((destructor));
static void on_load() //{
{
    pthread_mutex_lock(&__mutex);
    if(!initialized) {
        assert(state == nullptr);
        state = luaL_newstate();
        assert(state != nullptr);
        luaL_openlibs(state);
        initialized = true;
    }
    pthread_mutex_unlock(&__mutex);
} //}
static void on_unload() //{
{
    pthread_mutex_lock(&__mutex);
    if(initialized) {
        assert(state != nullptr);
        lua_close(state);
        state = nullptr;
        initialized = false;
    }
    pthread_mutex_unlock(&__mutex);
} //}

