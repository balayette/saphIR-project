#include "types.hh"

namespace types
{
std::string str[] = {"int", "string", "void", "invalid"};

std::string &ty_to_string(ty t) { return str[static_cast<int>(t)]; }

bool are_compatible(ty t1, ty t2) { return t1 == t2; }
} // namespace types
