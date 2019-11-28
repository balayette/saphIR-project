#pragma once
#include "ir-visitor.hh"
#include "ir.hh"

namespace backend
{
class default_ir_visitor : public ir_visitor
{
      public:
	virtual void visit_cnst(tree::cnst &) override {}
	virtual void visit_name(tree::name &) override {}
	virtual void visit_temp(tree::temp &) override {}
	virtual void visit_binop(tree::binop &n) override
	{
		n.lhs_->accept(*this);
		n.rhs_->accept(*this);
	}
	virtual void visit_mem(tree::mem &n) override { n.e_->accept(*this); }
	virtual void visit_call(tree::call &n) override
	{
		for (auto *a : n.args_)
			a->accept(*this);
	}
	virtual void visit_eseq(tree::eseq &n) override
	{
		n.lhs_->accept(*this);
		n.rhs_->accept(*this);
	}
	virtual void visit_move(tree::move &n) override
	{
		n.lhs_->accept(*this);
		n.rhs_->accept(*this);
	}
	virtual void visit_sexp(tree::sexp &n) override { n.e_->accept(*this); }
	virtual void visit_jump(tree::jump &n) override
	{
		n.dest_->accept(*this);
	}
	virtual void visit_cjump(tree::cjump &n) override
	{
		n.lhs_->accept(*this);
		n.lhs_->accept(*this);
	}
	virtual void visit_seq(tree::seq &n) override
	{
		for (auto *s : n.body_)
			s->accept(*this);
	}
	virtual void visit_label(tree::label &) override {}
};
} // namespace backend
