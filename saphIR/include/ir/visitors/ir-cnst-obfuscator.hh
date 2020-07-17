#pragma once
#include "ir-cloner-visitor.hh"

namespace ir
{
class ir_cnst_obfuscator : public ir_cloner_visitor
{
      public:
	ir_cnst_obfuscator(mach::target &target) : ir_cloner_visitor(target) {}
	virtual void visit_cnst(tree::cnst &) override;
};
} // namespace ir
