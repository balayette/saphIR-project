#pragma once

#include <string>

namespace types
{
enum class ty { INT, STRING, VOID, INVALID };

std::string &ty_to_string(ty t);

bool are_compatible(ty t1, ty t2);
} // namespace types
