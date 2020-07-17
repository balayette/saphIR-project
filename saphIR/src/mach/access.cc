#include "mach/access.hh"
#include "utils/assert.hh"

#include <array>

namespace mach
{
access::access(mach::target &target, utils::ref<types::ty> &ty)
    : target_(target), ty_(ty)
{
}

std::ostream &operator<<(std::ostream &os, const access &a)
{
	return a.print(os);
}
} // namespace mach
