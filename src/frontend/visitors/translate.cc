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

	auto *movt = new tree::move(new tree::temp(ret, types::integer_type()),
				    new tree::cnst(1));
	auto *movf = new tree::move(new tree::temp(ret, types::integer_type()),
				    new tree::cnst(0));

	auto *body = new tree::seq({cj, lt, movt, je, lf, movf, le});

	tree::rexp value = new tree::temp(ret, types::integer_type());

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

/*
 * References to structs need to return the address of the struct, but
 * references to pointers to structs stored in the stack need to return
 * the value of the pointer.
 * Cases:
 * - Of type struct_ty:
 *     - is a pointer to struct => exp
 *     - otherwise => addr
 * - otherwise => exp
 */
static tree::rexp access_to_exp(mach::access &access)
{
	if (!access.ty_.as<types::struct_ty>())
		return access.exp();
	if (access.ty_->ptr_)
		return access.exp();

	auto exp = access.addr();
	exp->ty_->ptr_--;
	return exp;
}

/*
 * lhs and rhs are binop(...), with type struct_ty
 */
exp *translate_visitor::struct_copy(ir::tree::rexp lhs, ir::tree::rexp rhs)
{
	std::cout << "struct_copy(" << lhs->ty_->to_string() << ", "
		  << rhs->ty_->to_string() << ")\n";

	auto st = lhs->ty_.as<types::struct_ty>();
	ASSERT(st && rhs->ty_.as<types::struct_ty>(),
	       "lhs and rhs have to be structs");

	auto s = new ir::tree::seq({});
	auto dst_base = lhs;
	auto src_base = rhs;

	utils::temp dst_temp;
	utils::temp src_temp;

	s->children_.push_back(new tree::move(
		new tree::temp(dst_temp, types::integer_type()), dst_base));
	s->children_.push_back(new tree::move(
		new tree::temp(src_temp, types::integer_type()), src_base));

	size_t offt = 0;
	for (size_t i = 0; i < st->types_.size(); i++) {
		tree::exp *dst_exp = new tree::binop(
			ops::binop::PLUS,
			new tree::temp(dst_temp, types::integer_type()),
			new tree::cnst(offt));
		tree::exp *src_exp = new tree::binop(
			ops::binop::PLUS,
			new tree::temp(src_temp, types::integer_type()),
			new tree::cnst(offt));

		dst_exp->ty_ = st->types_[i]->clone();
		src_exp->ty_ = st->types_[i]->clone();

		if (dst_exp->ty_->ptr_
		    || !dst_exp->ty_.as<types::struct_ty>()) {
			// scalar, so going to be a simple copy on the next
			// recursion
			dst_exp->ty_->ptr_++;
			dst_exp = new tree::mem(dst_exp);
			src_exp->ty_->ptr_++;
			src_exp = new tree::mem(src_exp);
		}

		s->children_.push_back(copy(dst_exp, src_exp)->un_nx());
		offt += st->types_[i]->size_;
	}

	return new nx(s);
}

/*
 * lhs is a binop(...), with type struct_ty
 */
exp *translate_visitor::braceinit_copy(ir::tree::rexp lhs,
				       utils::ref<ir::tree::braceinit> rhs)
{
	std::cout << "braceinit_copy(" << lhs->ty_->to_string() << ", "
		  << rhs->ty_->to_string() << ")\n";

	auto bit = rhs->ty_.as<types::braceinit_ty>();
	auto st = lhs->ty_.as<types::struct_ty>();
	ASSERT(bit && !rhs->ty_.as<types::struct_ty>(),
	       "rhs has to be a brace init");

	auto s = new ir::tree::seq({});
	auto base = lhs;
	auto exps = rhs->exps();

	utils::temp base_temp;
	s->children_.push_back(new tree::move(
		new tree::temp(base_temp, types::integer_type()), base));

	size_t offt = 0;
	for (size_t i = 0; i < exps.size(); i++) {
		tree::exp *dst_exp = new tree::binop(
			ops::binop::PLUS,
			new tree::temp(base_temp, types::integer_type()),
			new tree::cnst(offt));

		dst_exp->ty_ = st->types_[i]->clone();

		if (dst_exp->ty_->ptr_
		    || !dst_exp->ty_.as<types::struct_ty>()) {
			// scalar, so going to be a simple copy on the next
			// recursion
			dst_exp->ty_->ptr_++;
			dst_exp = new tree::mem(dst_exp);
		}

		s->children_.push_back(copy(dst_exp, exps[i])->un_nx());
		offt += bit->types_[i]->size_;
	}

	return new nx(s);
}


exp *translate_visitor::copy(ir::tree::rexp lhs, ir::tree::rexp rhs)
{
	std::cout << "copy(" << lhs->ty_->to_string() << ", "
		  << rhs->ty_->to_string() << ")\n";

	/*
	 * We're past type checking, so dst and rhs are consistent.
	 * Multiple cases:
	 * - lhs is a scalar (including all pointers) => emit a move
	 * - lhs is a struct
	 *      - rhs is another struct => recurse for every member
	 *      with a mem node that points to the member. If the member
	 *      is a nested struct (not a pointer), do not emit the mem node,
	 *      and make sure that the type of the expression is the type
	 *      of the nested struct
	 *      - rhs is a brace init => evaluate the expressions, and recurse
	 *      with the same rules.
	 */

	// scalars
	// XXX: functions can't return structs by value (it is ABI dependant)
	if (rhs->ty_->ptr_ > 0 || rhs->ty_.as<types::builtin_ty>()
	    || rhs->ty_.as<types::fun_ty>())
		return new nx(new ir::tree::move(lhs, rhs));

	// lhs is a struct
	// rhs is a struct
	if (auto st = rhs->ty_.as<types::struct_ty>())
		return struct_copy(lhs, rhs);

	// rhs is a brace init
	return braceinit_copy(lhs, rhs.as<tree::braceinit>());
}

void translate_visitor::visit_ref(ref &e)
{
	ret_ = new ex(access_to_exp(*e.dec_->access_));
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
					args, e.fdec_->type_);

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

	ret_ = copy(lhs->un_ex(), rhs->un_ex());
}

void translate_visitor::visit_locdec(locdec &s)
{
	if (!s.rhs_)
		return;

	auto lhs = access_to_exp(*s.access_);

	s.rhs_->accept(*this);

	ret_ = copy(lhs, ret_->un_ex());
}

void translate_visitor::visit_ret(ret &s)
{
	if (!s.e_) {
		ret_ = new nx(new ir::tree::jump(new ir::tree::name(ret_lbl_),
						 {ret_lbl_}));
		return;
	}
	s.e_->accept(*this);
	auto lhs = ret_->un_ex();
	ret_ = new nx(new ir::tree::seq({
		new ir::tree::move(new ir::tree::temp(mach::rv(), lhs->ty_),
				   lhs),
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
	mach::frame frame(unique_label("init_vars"), {}, {});
	init_fun_ = new mach::fun_fragment(
		frame.proc_entry_exit_1(body, ret_lbl), frame, ret_lbl,
		unique_label("init_vars_epi"));
}

void translate_visitor::visit_globaldec(globaldec &s)
{
	s.rhs_->accept(*this);
	init_funs_.push_back(
		copy(access_to_exp(*s.access_), ret_->un_ex())->un_nx());
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
	// structs don't have a mem node.
	if (auto r = ret.as<ir::tree::mem>())
		ret_ = new ex(r->e());
	else {
		ret->ty_ = ret->ty_->clone();
		ret->ty_->ptr_++;
		ret_ = new ex(ret);
	}
}

/*
 * e.e_ is a binop(...), which points to the struct
 * if the member is a struct, then don't emit the mem node
 */
void translate_visitor::visit_memberaccess(memberaccess &e)
{
	auto st = e.e_->ty_.as<types::struct_ty>();
	auto mem_ty = st->member_ty(e.member_);
	size_t offt = st->member_offset(e.member_);

	e.e_->accept(*this);
	auto exp = ret_->un_ex();

	ir::tree::exp *dst =
		new tree::binop(ops::binop::PLUS, exp, new tree::cnst(offt));
	dst->ty_ = mem_ty->clone();

	if (dst->ty_->ptr_ || !dst->ty_.as<types::braceinit_ty>()) {
		// the member is a scalar, so return the value and not the
		// address
		dst->ty_->ptr_++;
		dst = new tree::mem(dst);
	}

	ret_ = new ex(dst);
}

void translate_visitor::visit_braceinit(braceinit &e)
{
	auto bi = new ir::tree::braceinit(e.ty_, {});

	for (auto &c : e.exps_) {
		c->accept(*this);
		bi->children_.push_back(ret_->un_ex());
	}

	ret_ = new ex(bi);
}
} // namespace frontend::translate
