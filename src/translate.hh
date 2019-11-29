#pragma once

#include "ir.hh"
#include "default-visitor.hh"
#include "scoped.hh"
#include <unordered_map>
#include <vector>

namespace frontend::translate
{
class exp
{
      public:
	virtual ~exp() = default;

	virtual backend::tree::rexp un_ex() = 0;
	virtual backend::tree::rstm un_nx() = 0;
	virtual backend::tree::rstm un_cx(const temp::label &t,
					  const temp::label &f) = 0;
};

class cx : public exp
{
      public:
	cx(frontend::cmpop op, backend::tree::rexp l, backend::tree::rexp r);

	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	frontend::cmpop op_;
	backend::tree::rexp l_;
	backend::tree::rexp r_;
};

class ex : public exp
{
      public:
	ex(backend::tree::rexp e);
	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::rexp e_;
};

class nx : public exp
{
      public:
	nx(backend::tree::rstm s);
	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::rstm s_;
};

class translate_visitor : public default_visitor
{
      public:
	void visit_ref(ref &e) override
	{
		ret_ = new ex(e.dec_->access_->exp());
	}

	void visit_num(num &e) override
	{
		ret_ = new ex(new backend::tree::cnst(e.value_));
	}

	void visit_call(call &e) override
	{
		std::vector<backend::tree::rexp> args;
		for (auto a : e.args_) {
			a->accept(*this);
			args.emplace_back(ret_->un_ex());
		}

		auto *call = new backend::tree::call(
			new backend::tree::name(e.fdec_->name_.get()), args);

		ret_ = new ex(call);
	}

	void visit_bin(bin &e) override
	{
		e.lhs_->accept(*this);
		auto left = ret_;
		e.rhs_->accept(*this);
		auto right = ret_;

		ret_ = new ex(new backend::tree::binop(e.op_, left->un_ex(),
						       right->un_ex()));
	}

	void visit_cmp(cmp &e) override
	{
		e.lhs_->accept(*this);
		auto left = ret_;
		e.rhs_->accept(*this);
		auto right = ret_;

		ret_ = new cx(e.op_, left->un_ex(), right->un_ex());
	}

	void visit_forstmt(forstmt &s) override
	{
		s.init_->accept(*this);
		auto init = ret_;
		s.cond_->accept(*this);
		auto cond = ret_;
		s.action_->accept(*this);
		auto action = ret_;

		auto body = new backend::tree::seq({});
		for (auto *s : s.body_) {
			s->accept(*this);
			body->body_.push_back(ret_->un_nx());
		}

		::temp::label cond_lbl;
		::temp::label body_lbl;
		::temp::label end_lbl;

		/*
		 * for (int a = 0; a != 10; a = a + 1)
		 * 	body
		 * rof
		 *
		 * int a = 0;
		 * cond_lbl:
		 * a != 10, body_lbl, end_lbl
		 * body_lbl:
		 * body
		 * action
		 * jump cond_lbl
		 * end_lbl:
		 */

		ret_ = new nx(new backend::tree::seq({
			init->un_nx(),
			new backend::tree::label(cond_lbl),
			cond->un_cx(body_lbl, end_lbl),
			new backend::tree::label(body_lbl),
			body,
			action->un_nx(),
			new backend::tree::jump(
				new backend::tree::name(cond_lbl), {cond_lbl}),
			new backend::tree::label(end_lbl),
		}));
	}

	void visit_ifstmt(ifstmt &s) override
	{
		s.cond_->accept(*this);
		auto cond = ret_;

		auto ibody = new backend::tree::seq({});
		for (auto *s : s.ibody_) {
			s->accept(*this);
			ibody->body_.push_back(ret_->un_nx());
		}
		auto ebody = new backend::tree::seq({});
		for (auto *s : s.ebody_) {
			s->accept(*this);
			ebody->body_.push_back(ret_->un_nx());
		}

		::temp::label i_lbl;
		::temp::label e_lbl;
		::temp::label end_lbl;

		/*
		 * if (a == 2)
		 *  ibody
		 * else
		 *  ebody
		 * fi
		 *
		 * a == 2, i_lbl, e_lbl
		 * i_lbl:
		 * ibody
		 * jump end_lbl
		 * e_lbl:
		 * ebody
		 * end_lbl:
		 */

		ret_ = new nx(new backend::tree::seq({
			cond->un_cx(i_lbl, e_lbl),
			new backend::tree::label(i_lbl),
			ibody,
			new backend::tree::jump(
				new backend::tree::name(end_lbl), {end_lbl}),
			new backend::tree::label(e_lbl),
			ebody,
			new backend::tree::label(end_lbl),
		}));
	}

	void visit_ass(ass &s) override
	{
		s.lhs_->accept(*this);
		auto lhs = ret_;
		s.rhs_->accept(*this);
		auto rhs = ret_;

		ret_ = new nx(
			new backend::tree::move(lhs->un_ex(), rhs->un_ex()));
	}

	void visit_vardec(vardec &s) override
	{
		s.rhs_->accept(*this);
		auto rhs = ret_;

		ret_ = new nx(new backend::tree::move(s.access_->exp(),
						      rhs->un_ex()));
	}

	void visit_ret(ret &s) override
	{
		if (!s.e_) {
			ret_ = new nx(new backend::tree::jump(
				new backend::tree::name(ret_lbl_), {ret_lbl_}));
			return;
		}
		s.e_->accept(*this);
		auto lhs = ret_;
		ret_ = new nx(new backend::tree::seq({
			new backend::tree::move(
				new backend::tree::temp(frame::rv()),
				lhs->un_ex()),
			new backend::tree::jump(
				new backend::tree::name(ret_lbl_), {ret_lbl_}),
		}));
	}

	void visit_str_lit(str_lit &e) override
	{
		::temp::label lab;

		ret_ = new ex(new backend::tree::name(lab));

		str_lits_.emplace(lab, e);
	}

	void visit_fundec(fundec &s) override
	{
		ret_lbl_.enter(::temp::label());

		auto body = new backend::tree::seq({});
		for (auto *stm : s.body_) {
			stm->accept(*this);
			body->body_.push_back(ret_->un_nx());
		}

		funs_.emplace_back(s.frame_->proc_entry_exit_1(body), *s.frame_,
				   ret_lbl_);

		ret_lbl_.leave();
	}

      public:
	utils::ref<exp> ret_;
	scoped_var<::temp::label> ret_lbl_;
	std::unordered_map<::temp::label, str_lit> str_lits_;
	std::vector<frame::fun_fragment> funs_;
};

} // namespace frontend::translate
