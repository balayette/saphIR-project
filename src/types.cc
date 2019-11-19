#include "types.hh"

namespace types
{
const std::string str[] = {"int", "string", "void", "invalid"};

std::string ty::to_string() const
{
	std::string ret(str[static_cast<int>(ty_)]);
	for (unsigned i = 0; i < ptr_; i++)
		ret += '*';
	return ret;
}
} // namespace types
