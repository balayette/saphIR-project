#include "ir/ir.hh"
#include "mach/target.hh"

namespace ir::tree
{
cnst::cnst(int value) : exp(mach::TARGET().integer_type()), value_(value) {}
} // namespace ir::tree
