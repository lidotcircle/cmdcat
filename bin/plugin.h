#pragma once

#include <string>
#include <map>
#include <set>
using namespace std;

#include "server.h"


using ProcessTreeTransform = string (*)(const ProcessTree* tree, const map<string, string>&);

/** c++ plugin */
extern map<string, pair<ProcessTreeTransform, string>> c_plugin;
void setup_c_plugins();

