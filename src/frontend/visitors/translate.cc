#include "frontend/visitors/translate.hh"
#include "utils/temp.hh"
#include "frontend/ops.hh"
#include <iostream>
#include "utils/assert.hh"
#include "frontend/exp.hh"
#include "ir/ir.hh"
#include "ir/visitors/ir-pretty-printer.hh"

#define TRANS_DEBUG 0

namespace frontend::translate
{

using namespace ir;

cx::cx(ops::cmpop op, tree::rexp l, tree::rexp r) : op_(op), l_(l), r_(r)
{
#if TRANS_DEBUG
	ir::ir_pretty_printer p(std::cout);
	std::cout << "cx: " << ops::cmpop_to_string(op) << '\n';
	l_->accept(p);
	r_->accept(p);
#endif
}

tree::rexp cx::un_ex()
{
	utils::temp ret;
	auto t_lbl = utils::label();
	auto f_lbl = utils::label();
	auto e_lbl = utils::label();

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

tree::rstm cx::un_cx(const utils::label &t, const utils::label &f)
{
	return new tree::cjump(op_, l_, r_, t, f);
}

ex::ex(ir::tree::rexp e) : e_(e)
{
#if TRANS_DEBUG
	ir::ir_pretty_printer p(std::cout);
	std::cout << "ex:\n";
	e_->accept(p);
#endif
}

tree::rexp ex::un_ex() { return e_; }

tree::rstm ex::un_nx() { return new tree::sexp(e_); }

tree::rstm ex::un_cx(const utils::label &t, const utils::label &f)
{
	return new tree::cjump(ops::cmpop::NEQ, e_, new tree::cnst(0), t, f);
}

nx::nx(ir::tree::rstm s) : s_(s)
{
#if TRANS_DEBUG
	ir::ir_pretty_printer p(std::cout);
	std::cout << "nx:\n";
	s_->accept(p);
#endif
}

tree::rexp nx::un_ex() { ASSERT(false, "Can't un_ex an nx"); }

tree::rstm nx::un_nx() { return s_; }

tree::rstm nx::un_cx(const utils::label &, const utils::label &)
{
	ASSERT(false, "Can't un_cx an nx");
}

void translate_visitor::visit_ref(ref &e)
{
	ret_ = new ex(e.dec_->access_->exp());
}

void translate_visitor::visit_num(num &e)
{
	ret_ = new ex(new ir::tree::cnst(e.value_));
}

void translate_visitor::visit_call(call &e)
{
	std::vector<ir::tree::rexp> args;
	for (auto a : e.args_) {
		a->accept(*this);
		args.emplace_back(ret_->un_ex());
	}

	auto *call = new ir::tree::call(new ir::tree::name(e.fdec_->name_),
					args, e.fdec_->variadic_);

	ret_ = new ex(call);
}

void translate_visitor::visit_bin(bin &e)
{
	e.lhs_->accept(*this);
	auto left = ret_;
	e.rhs_->accept(*this);
	auto right = ret_;

	ret_ = new ex(
		new ir::tree::binop(e.op_, left->un_ex(), right->un_ex()));
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

	std::vector<ir::tree::rstm> stms;
	for (auto *s : s.body_) {
		s->accept(*this);
		stms.push_back(ret_->un_nx());
	}
	auto body = new ir::tree::seq(stms);

	utils::label cond_lbl;
	utils::label body_lbl;
	utils::label end_lbl;

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

	ret_ = new nx(new ir::tree::seq({
		init->un_nx(),
		new ir::tree::label(cond_lbl),
		cond->un_cx(body_lbl, end_lbl),
		new ir::tree::label(body_lbl),
		body,
		action->un_nx(),
		new ir::tree::jump(new ir::tree::name(cond_lbl), {cond_lbl}),
		new ir::tree::label(end_lbl),
	}));
}

void translate_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);
	auto cond = ret_;

	std::vector<ir::tree::rstm> istms;
	for (auto *s : s.ibody_) {
		s->accept(*this);
		istms.push_back(ret_->un_nx());
	}
	auto ibody = new ir::tree::seq(istms);

	std::vector<ir::tree::rstm> estms;
	for (auto *s : s.ebody_) {
		s->accept(*this);
		estms.push_back(ret_->un_nx());
	}
	auto ebody = new ir::tree::seq(estms);

	utils::label i_lbl;
	utils::label e_lbl;
	utils::label end_lbl;

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

	ret_ = new nx(new ir::tree::seq({
		cond->un_cx(i_lbl, e_lbl),
		new ir::tree::label(i_lbl),
		ibody,
		new ir::tree::jump(new ir::tree::name(end_lbl), {end_lbl}),
		new ir::tree::label(e_lbl),
		ebody,
		new ir::tree::label(end_lbl),
	}));
}

void translate_visitor::visit_ass(ass &s)
{
	s.lhs_->accept(*this);
	auto lhs = ret_;
	s.rhs_->accept(*this);
	auto rhs = ret_;

	ret_ = new nx(new ir::tree::move(lhs->un_ex(), rhs->un_ex()));
}

void translate_visitor::visit_locdec(locdec &s)
{
	if (!s.rhs_)
		return;

	s.rhs_->accept(*this);
	auto rhs = ret_;

	ret_ = new nx(new ir::tree::move(s.access_->exp(), rhs->un_ex()));
}

void translate_visitor::visit_ret(ret &s)
{
	if (!s.e_) {
		ret_ = new nx(new ir::tree::jump(new ir::tree::name(ret_lbl_),
						 {ret_lbl_}));
		return;
	}
	s.e_->accept(*this);
	auto lhs = ret_;
	ret_ = new nx(new ir::tree::seq({
		new ir::tree::move(new ir::tree::temp(mach::rv()),
				   lhs->un_ex()),
		new ir::tree::jump(new ir::tree::name(ret_lbl_), {ret_lbl_}),
	}));
}

void translate_visitor::visit_str_lit(str_lit &e)
{
	utils::label lab = unique_label("str_lit");

	ret_ = new ex(new ir::tree::name(lab));

	str_lits_.emplace(lab, e);
}

void translate_visitor::visit_decs(decs &s)
{
	default_visitor::visit_decs(s);

	if (init_funs_.size() == 0)
		return;

	auto body = new ir::tree::seq(init_funs_);
	utils::label ret_lbl = unique_label("init_vars_ret");
	mach::frame frame(unique_label("init_vars"), {});
	init_fun_ = new mach::fun_fragment(
		frame.proc_entry_exit_1(body, ret_lbl), frame, ret_lbl,
		unique_label("init_vars_epi"));
}

void translate_visitor::visit_globaldec(globaldec &s)
{
	s.rhs_->accept(*this);
	init_funs_.push_back(
		new ir::tree::move(s.access_->exp(), ret_->un_ex()));
}

void translate_visitor::visit_funprotodec(funprotodec &)
{
	// Ignore prototypes.
}

void translate_visitor::visit_fundec(fundec &s)
{
	ret_lbl_.enter(unique_label("ret"));

	std::vector<ir::tree::rstm> stms;
	for (auto *stm : s.body_) {
		stm->accept(*this);
		stms.push_back(ret_->un_nx());
	}
	auto body = new ir::tree::seq(stms);

	funs_.emplace_back(s.frame_->proc_entry_exit_1(body, ret_lbl_),
			   *s.frame_, ret_lbl_,
			   unique_label(s.name_.get() + "_epi"));

	ret_lbl_.leave();
}

void translate_visitor::visit_deref(deref &e)
{
	e.e_->accept(*this);
	ret_ = new ex(new ir::tree::mem(ret_->un_ex()));
}

void translate_visitor::visit_addrof(addrof &e)
{
	e.e_->accept(*this);
	auto ret = ret_->un_ex();
	// When taking the address of a variable, we know that it escapes and
	// is stored in memory. Because we need the address and not the value,
	// we remove the mem node.
	// There are no pointes in Tiger, but I think that this is how they
	// work.
	auto r = ret_->un_ex().as<ir::tree::mem>();
	ASSERT(r, "Taking the address of a non escaping variable.");

	ret_ = new ex(r->e());
}
} // namespace frontend::translate
