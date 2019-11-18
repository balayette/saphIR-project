#include "types.hh"

namespace types
{
std::string str[] = {"int", "string", "void", "invalid", "int*", "string*"};

const std::string &ty::to_string() const
{
	if (!ptr_)
		return str[static_cast<int>(ty_)];
	return str[4 + static_cast<int>(ty_)];
}
} // namespace types
