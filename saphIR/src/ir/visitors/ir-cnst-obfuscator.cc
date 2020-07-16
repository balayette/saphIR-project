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

	ret_ = new tree::binop(
		ops::binop::BITXOR, new tree::cnst(n.value_ ^ key),
		new tree::cnst(key), mach::TARGET().integer_type());
}
} // namespace ir
