#include "ir/ir.hh"
#include "mach/target.hh"

namespace ir::tree
{
cnst::cnst(mach::target &target, uint64_t value)
    : exp(target, target.integer_type()), value_(value)
{
}

cnst::cnst(mach::target &target, uint64_t value, types::signedness signedness,
	   size_t sz)
    : exp(target, target.integer_type(signedness, sz)), value_(value)
{
}
} // namespace ir::tree
