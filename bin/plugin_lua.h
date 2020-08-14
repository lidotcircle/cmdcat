#pragma once

#include "server.h"

#include <string>
#include <map>
using namespace std;

bool setup_lua_plugins(const string& file);
map<string, string> list_lua_plugins();
string invoke_plugin(const string& plugin, const map<string,string>& argv, ProcessTree* data, bool& error);

#define PLUGIN_PREFIX "PLG_"
#define DESCRIPTION_PREFIEX "HELP_"

