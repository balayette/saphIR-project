#pragma once

#include <string>

enum class ty { INT, STRING, VOID, INVALID };

std::string& ty_to_string(ty t);

bool are_compatible(ty t1, ty t2);
