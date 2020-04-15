#include "ir/visitors/ir-arith-optimizer.hh"
#include "ir/visitors/ir-pretty-printer.hh"

#define OPTIMIZED(S, D)                                                        \
	do {                                                                   \
		ir::ir_pretty_printer pir(std::cout);                          \
		std::cout << "Optimizing arith from\n";                        \
		(S)->accept(pir);                                              \
		std::cout << "To\n";                                           \
		(D)->accept(pir);                                              \
	} while (0)

namespace ir
{
void ir_arith_optimizer::visit_binop(tree::binop &n)
{
	ir_cloner_visitor::visit_binop(n);
	if (n.op_ != ops::binop::PLUS)
		return;

	auto bin = ret_.as<tree::binop>();

	auto lhs = bin->lhs().as<tree::cnst>();
	auto rhs = bin->rhs().as<tree::cnst>();

	if ((lhs && rhs) || (!lhs && !rhs))
		return;

	if (lhs && !rhs)
		return;

	std::swap(bin->children_[0], bin->children_[1]);
	OPTIMIZED(&n, bin);

	// We now have cascading binops with constants on the left
	auto binr = bin->rhs().as<tree::binop>();
	if (!binr || binr->op_ != ops::binop::PLUS)
		return;

	auto lhscnst = binr->lhs().as<tree::cnst>();
	if (!lhscnst)
		return;

	auto mycnst = bin->lhs().as<tree::cnst>();
	mycnst->value_ += lhscnst->value_;

	bin->children_[1] = binr->rhs();
	OPTIMIZED(&n, bin);

	return;
}
} // namespace ir
