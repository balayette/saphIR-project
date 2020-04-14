#pragma once
#include "ir-cloner-visitor.hh"

namespace ir
{
class ir_cnst_obfuscator : public ir_cloner_visitor
{
	virtual void visit_cnst(tree::cnst &) override;
};
} // namespace ir
