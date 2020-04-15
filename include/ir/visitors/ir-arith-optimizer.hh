#pragma once
#include "ir-cloner-visitor.hh"

namespace ir
{
/*
 * Move constants in binary ops to the left hand side
 */
class ir_arith_optimizer : public ir_cloner_visitor
{
      public:
	virtual void visit_binop(tree::binop &) override;
};
} // namespace ir
