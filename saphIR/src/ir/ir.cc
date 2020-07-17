#include "ir/ir.hh"
#include "mach/target.hh"

namespace ir::tree
{
cnst::cnst(mach::target &target, uint64_t value)
    : exp(target, target.integer_type()), value_(value)
{
}
} // namespace ir::tree
