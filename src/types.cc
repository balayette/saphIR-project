#include "types.hh"

std::string str[] = {"int", "string", "void"};

std::string &ty_to_string(ty t) { return str[static_cast<int>(t)]; }
