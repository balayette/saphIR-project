#pragma once
#include "visitor.hh"
#include "stmt.hh"

class default_visitor : public visitor
{
      public:
	virtual void visit_decs(decs &s) override
	{
		for (auto *f : s.fundecs_)
			f->accept(*this);
		for (auto *v : s.vardecs_)
			v->accept(*this);
	};

	virtual void visit_vardec(vardec &s) override { s.rhs_->accept(*this); }

	virtual void visit_argdec(argdec &) override {}

	virtual void visit_fundec(fundec &s) override
	{
		for (auto *arg : s.args_)
			arg->accept(*this);
		for (auto *b : s.body_)
			b->accept(*this);
	}

	virtual void visit_sexp(sexp &s) override { s.e_->accept(*this); }

	virtual void visit_ret(ret &s) override
	{
		if (s.e_ != nullptr)
			s.e_->accept(*this);
	}

	virtual void visit_ifstmt(ifstmt &s) override
	{
		s.cond_->accept(*this);
		for (auto *i : s.ibody_)
			i->accept(*this);
		for (auto *e : s.ebody_)
			e->accept(*this);
	}

	virtual void visit_forstmt(forstmt &s) override
	{
		s.init_->accept(*this);
		s.cond_->accept(*this);
		s.action_->accept(*this);

		for (auto *b : s.body_)
			b->accept(*this);
	}

	virtual void visit_bin(bin &e) override
	{
		e.lhs_->accept(*this);
		e.rhs_->accept(*this);
	}

	virtual void visit_ass(ass &e) override { e.rhs_->accept(*this); }

	virtual void visit_cmp(cmp &e) override
	{
		e.lhs_->accept(*this);
		e.rhs_->accept(*this);
	}

	virtual void visit_num(num &) override {}

	virtual void visit_ref(ref &) override {}

	virtual void visit_call(call &e) override
	{
		for (auto *a : e.args_)
			a->accept(*this);
	}
};
