#pragma once
#include "ir-cloner-visitor.hh"

namespace ir
{
class ir_binop_optimizer : public ir_cloner_visitor
{
      public:
	ir_binop_optimizer(mach::target &target) : ir_cloner_visitor(target) {}
	virtual void visit_binop(tree::binop &) override;
};
} // namespace ir
