#include "ir/visitors/ir-cnst-obfuscator.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "ir/types.hh"
#include "mach/target.hh"
#include <cstdlib>

namespace ir
{
void ir_cnst_obfuscator::visit_cnst(tree::cnst &n)
{
	uint32_t key = rand();

	ret_ = target_.make_binop(
		ops::binop::BITXOR, target_.make_cnst(n.value_ ^ key),
		target_.make_cnst(key), target_.integer_type());
}
} // namespace ir
