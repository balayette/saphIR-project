#include "ir/visitors/ir-binop-optimizer.hh"
#include "ir/visitors/ir-pretty-printer.hh"

#define OPTIMIZED(S, D)                                                        \
	do {                                                                   \
		ir::ir_pretty_printer pir(std::cout);                          \
		std::cout << "Optimizing from\n";                              \
		(S)->accept(pir);                                              \
		std::cout << "To\n";                                           \
		(D)->accept(pir);                                              \
	} while (0)

namespace ir
{
void ir_binop_optimizer::visit_binop(tree::binop &n)
{
	ir_cloner_visitor::visit_binop(n);
	auto bin = ret_.as<tree::binop>();

	auto lhs = bin->lhs().as<tree::cnst>();
	auto rhs = bin->rhs().as<tree::cnst>();

	if (!lhs && !rhs)
		return;

	if ((!lhs && rhs) || (lhs && !rhs)) {
		auto cnst = lhs ? lhs : rhs;
		auto var = lhs ? bin->rhs() : bin->lhs();
		auto value = cnst->value_;

		if (n.op_ == ops::binop::MULT) {
			if (value == 0) {
				auto zero = new tree::cnst(0);
				zero->ty_ = bin->ty_->clone();
				ret_ = zero;

				OPTIMIZED(bin, ret_);
				return;
			}
			if (value == 1) {
				var->ty_ = bin->ty_->clone();
				ret_ = var;

				OPTIMIZED(bin, ret_);
				return;
			}
		}
		if (n.op_ == ops::binop::PLUS) {
			if (value == 0) {
				var->ty_ = bin->ty_->clone();
				ret_ = var;

				OPTIMIZED(bin, ret_);
				return;
			}
		}
		return;
	}

	int64_t value = 0;

	switch (n.op_) {
	case ops::binop::MINUS:
		value = lhs->value_ - rhs->value_;
		break;
	case ops::binop::PLUS:
		value = lhs->value_ + rhs->value_;
		break;
	case ops::binop::MULT:
		value = lhs->value_ * rhs->value_;
		break;
	case ops::binop::DIV:
		value = lhs->value_ / rhs->value_;
		break;
	case ops::binop::MOD:
		value = lhs->value_ % rhs->value_;
		break;
	case ops::binop::AND:
		value = lhs->value_ && rhs->value_;
		break;
	case ops::binop::OR:
		value = lhs->value_ || rhs->value_;
		break;
	case ops::binop::BITAND:
		value = lhs->value_ & rhs->value_;
		break;
	case ops::binop::BITOR:
		value = lhs->value_ | rhs->value_;
		break;
	case ops::binop::BITXOR:
		value = lhs->value_ ^ rhs->value_;
		break;
	case ops::binop::BITLSHIFT:
		value = (uint64_t)lhs->value_ >> rhs->value_;
		break;
	case ops::binop::BITRSHIFT:
		value = (uint64_t)lhs->value_ >> rhs->value_;
		break;
	case ops::binop::ARITHBITRSHIFT:
		value = (int64_t)lhs->value_ >> rhs->value_;
		break;
	}

	auto ret = new tree::cnst(value);
	ret->ty_ = bin->ty_->clone();

	ret_ = ret;
	OPTIMIZED(bin, ret_);
}
} // namespace ir
