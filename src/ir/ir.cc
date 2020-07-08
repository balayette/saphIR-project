#include "ir/ir.hh"
#include "mach/target.hh"

namespace ir::tree
{
cnst::cnst(uint64_t value) : exp(mach::TARGET().integer_type()), value_(value) {}
} // namespace ir::tree
