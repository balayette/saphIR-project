#pragma once
#include "ir-visitor.hh"
#include "ir/ir.hh"

namespace ir
{
class default_ir_visitor : public ir_visitor
{
      public:
	virtual void visit_cnst(tree::cnst &) override;
	virtual void visit_braceinit(tree::braceinit &) override;
	virtual void visit_name(tree::name &) override;
	virtual void visit_temp(tree::temp &) override;
	virtual void visit_binop(tree::binop &n) override;
	virtual void visit_mem(tree::mem &n) override;
	virtual void visit_call(tree::call &n) override;
	virtual void visit_eseq(tree::eseq &n) override;
	virtual void visit_move(tree::move &n) override;
	virtual void visit_sexp(tree::sexp &n) override;
	virtual void visit_jump(tree::jump &n) override;
	virtual void visit_cjump(tree::cjump &n) override;
	virtual void visit_seq(tree::seq &n) override;
	virtual void visit_label(tree::label &) override;
};
} // namespace ir
