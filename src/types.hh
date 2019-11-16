#pragma once

#include <string>

enum class ty { INT, STRING, VOID };

std::string& ty_to_string(ty t);
