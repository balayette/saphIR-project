#include "frontend/visitors/translate.hh"
#include "utils/temp.hh"
#include "frontend/ops.hh"
#include <iostream>
#include "frontend/exp.hh"
#include "ir/ir.hh"
#include "ir/visitors/ir-pretty-printer.hh"

#define TRANS_DEBUG 1

namespace frontend::translate
{

using namespace backend;

cx::cx(ops::cmpop op, tree::rexp l, tree::rexp r) : op_(op), l_(l), r_(r)
{
#if TRANS_DEBUG
	backend::ir_pretty_printer p(std::cout);
	std::cout << "cx: " << ops::cmpop_to_string(op) << '\n';
	l_->accept(p);
	r_->accept(p);
#endif
}

tree::rexp cx::un_ex()
{
	auto ret = temp::temp();
	auto t_lbl = temp::label();
	auto f_lbl = temp::label();
	auto e_lbl = temp::label();

	auto *lt = new tree::label(t_lbl);
	auto *lf = new tree::label(f_lbl);
	auto *le = new tree::label(e_lbl);

	auto *je = new tree::jump(new tree::name(e_lbl), {e_lbl});
	auto *cj = new tree::cjump(op_, l_, r_, t_lbl, f_lbl);

	auto *movt = new tree::move(new tree::temp(ret), new tree::cnst(1));
	auto *movf = new tree::move(new tree::temp(ret), new tree::cnst(0));

	auto *body = new tree::seq({cj, lt, movt, je, lf, movf, le});

	tree::rexp value = new tree::temp(ret);

	return new tree::eseq(body, value);
}

tree::rstm cx::un_nx()
{
	return new tree::seq({new tree::sexp(l_), new tree::sexp(r_)});
}

tree::rstm cx::un_cx(const temp::label &t, const temp::label &f)
{
	return new tree::cjump(op_, l_, r_, t, f);
}

ex::ex(backend::tree::rexp e) : e_(e)
{
#if TRANS_DEBUG
	backend::ir_pretty_printer p(std::cout);
	std::cout << "ex:\n";
	e_->accept(p);
#endif
}

tree::rexp ex::un_ex() { return e_; }

tree::rstm ex::un_nx() { return new tree::sexp(e_); }

tree::rstm ex::un_cx(const temp::label &t, const temp::label &f)
{
	return new tree::cjump(ops::cmpop::NEQ, e_, new tree::cnst(0), t, f);
}

nx::nx(backend::tree::rstm s) : s_(s)
{
#if TRANS_DEBUG
	backend::ir_pretty_printer p(std::cout);
	std::cout << "nx:\n";
	s_->accept(p);
#endif
}

tree::rexp nx::un_ex()
{
	std::cerr << "Can't un_ex an nx\n";
	std::exit(5);
}

tree::rstm nx::un_nx() { return s_; }

tree::rstm nx::un_cx(const temp::label &, const temp::label &)
{
	std::cerr << "Can't un_cx an nx\n";
	std::exit(5);
}

void translate_visitor::visit_ref(ref &e)
{
	ret_ = new ex(e.dec_->access_->exp());
}

void translate_visitor::visit_num(num &e)
{
	ret_ = new ex(new backend::tree::cnst(e.value_));
}

void translate_visitor::visit_call(call &e)
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

void translate_visitor::visit_bin(bin &e)
{
	e.lhs_->accept(*this);
	auto left = ret_;
	e.rhs_->accept(*this);
	auto right = ret_;

	ret_ = new ex(
		new backend::tree::binop(e.op_, left->un_ex(), right->un_ex()));
}

void translate_visitor::visit_cmp(cmp &e)
{
	e.lhs_->accept(*this);
	auto left = ret_;
	e.rhs_->accept(*this);
	auto right = ret_;

	ret_ = new cx(e.op_, left->un_ex(), right->un_ex());
}

void translate_visitor::visit_forstmt(forstmt &s)
{
	s.init_->accept(*this);
	auto init = ret_;
	s.cond_->accept(*this);
	auto cond = ret_;
	s.action_->accept(*this);
	auto action = ret_;

	std::vector<backend::tree::rstm> stms;
	for (auto *s : s.body_) {
		s->accept(*this);
		stms.push_back(ret_->un_nx());
	}
	auto body = new backend::tree::seq(stms);

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
		new backend::tree::jump(new backend::tree::name(cond_lbl),
					{cond_lbl}),
		new backend::tree::label(end_lbl),
	}));
}

void translate_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);
	auto cond = ret_;

	std::vector<backend::tree::rstm> istms;
	for (auto *s : s.ibody_) {
		s->accept(*this);
		istms.push_back(ret_->un_nx());
	}
	auto ibody = new backend::tree::seq(istms);

	std::vector<backend::tree::rstm> estms;
	for (auto *s : s.ebody_) {
		s->accept(*this);
		estms.push_back(ret_->un_nx());
	}
	auto ebody = new backend::tree::seq(estms);

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
		new backend::tree::jump(new backend::tree::name(end_lbl),
					{end_lbl}),
		new backend::tree::label(e_lbl),
		ebody,
		new backend::tree::label(end_lbl),
	}));
}

void translate_visitor::visit_ass(ass &s)
{
	s.lhs_->accept(*this);
	auto lhs = ret_;
	s.rhs_->accept(*this);
	auto rhs = ret_;

	ret_ = new nx(new backend::tree::move(lhs->un_ex(), rhs->un_ex()));
}

void translate_visitor::visit_vardec(vardec &s)
{
	s.rhs_->accept(*this);
	auto rhs = ret_;

	ret_ = new nx(new backend::tree::move(s.access_->exp(), rhs->un_ex()));
}

void translate_visitor::visit_ret(ret &s)
{
	if (!s.e_) {
		ret_ = new nx(new backend::tree::jump(
			new backend::tree::name(ret_lbl_), {ret_lbl_}));
		return;
	}
	s.e_->accept(*this);
	auto lhs = ret_;
	ret_ = new nx(new backend::tree::seq({
		new backend::tree::move(new backend::tree::temp(frame::rv()),
					lhs->un_ex()),
		new backend::tree::jump(new backend::tree::name(ret_lbl_),
					{ret_lbl_}),
	}));
}

void translate_visitor::visit_str_lit(str_lit &e)
{
	::temp::label lab;

	ret_ = new ex(new backend::tree::name(lab));

	str_lits_.emplace(lab, e);
}

void translate_visitor::visit_fundec(fundec &s)
{
	ret_lbl_.enter(::temp::label());

        std::vector<backend::tree::rstm> stms;
	for (auto *stm : s.body_) {
		stm->accept(*this);
		stms.push_back(ret_->un_nx());
	}
	auto body = new backend::tree::seq(stms);

	funs_.emplace_back(s.frame_->proc_entry_exit_1(body), *s.frame_,
			   ret_lbl_);

	ret_lbl_.leave();
}
} // namespace frontend::translate
