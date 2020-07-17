#include "frontend/visitors/translate.hh"
#include "utils/temp.hh"
#include "ir/ops.hh"
#include <iostream>
#include "utils/assert.hh"
#include "frontend/exp.hh"
#include "ir/ir.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "mach/target.hh"

#define TRANS_DEBUG 0

namespace frontend::translate
{
using namespace ir;

#define CX(Op, L, R) cx(target_, Op, L, R)
#define EX(E) ex(target_, E)
#define NX(S) nx(target_, S)

cx::cx(mach::target &target, ops::cmpop op, tree::rexp l, tree::rexp r)
    : exp(target), op_(op), l_(l), r_(r)
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

	auto *lt = target_.make_label(t_lbl);
	auto *lf = target_.make_label(f_lbl);
	auto *le = target_.make_label(e_lbl);

	auto *je = target_.make_jump(target_.make_name(e_lbl), {e_lbl});
	auto *cj = target_.make_cjump(op_, l_, r_, t_lbl, f_lbl);

	auto *movt = target_.make_move(
		target_.make_temp(ret, target_.integer_type()),
		target_.make_cnst(1));
	auto *movf = target_.make_move(
		target_.make_temp(ret, target_.integer_type()),
		target_.make_cnst(0));

	auto *body = target_.make_seq({cj, lt, movt, je, lf, movf, le});

	tree::rexp value = target_.make_temp(ret, target_.integer_type());

	return target_.make_eseq(body, value);
}

tree::rstm cx::un_nx()
{
	return target_.make_seq({target_.make_sexp(l_), target_.make_sexp(r_)});
}

tree::rstm cx::un_cx(const utils::label &t, const utils::label &f)
{
	return target_.make_cjump(op_, l_, r_, t, f);
}

ex::ex(mach::target &target, ir::tree::rexp e) : exp(target), e_(e)
{
#if TRANS_DEBUG
	ir::ir_pretty_printer p(std::cout);
	std::cout << "ex:\n";
	e_->accept(p);
#endif
}

tree::rexp ex::un_ex() { return e_; }

tree::rstm ex::un_nx() { return target_.make_sexp(e_); }

tree::rstm ex::un_cx(const utils::label &t, const utils::label &f)
{
	return target_.make_cjump(ops::cmpop::NEQ, e_, target_.make_cnst(0), t,
				  f);
}

nx::nx(mach::target &target, ir::tree::rstm s) : exp(target), s_(s)
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
 */
static tree::rexp access_to_exp(mach::access &access)
{
	if (types::is_scalar(&access.ty_) && !access.ty_.as<types::fun_ty>())
		return access.exp();

	auto exp = access.addr();
	exp->ty_ = deref_pointer_type(exp->ty_);
	return exp;
}

/*
 * lhs and rhs are binop(...), with type array_ty
 */
utils::ref<exp> translate_visitor::array_copy(ir::tree::rexp lhs,
					      ir::tree::rexp rhs)
{
	std::cout << "array_copy(" << lhs->ty_->to_string() << ", "
		  << rhs->ty_->to_string() << ")\n";

	auto at = lhs->ty_.as<types::array_ty>();
	ASSERT(at && rhs->ty_.as<types::array_ty>(),
	       "lhs and rhs have to be arrays");

	auto s = target_.make_seq({});
	auto dst_base = lhs;
	auto src_base = rhs;

	utils::temp dst_temp;
	utils::temp src_temp;

	s->children_.push_back(target_.make_move(
		target_.make_temp(dst_temp, target_.integer_type()), dst_base));
	s->children_.push_back(target_.make_move(
		target_.make_temp(src_temp, target_.integer_type()), src_base));

	size_t offt = 0;
	for (size_t i = 0; i < at->n_; i++) {
		tree::exp *dst_exp = target_.make_binop(
			ops::binop::PLUS,
			target_.make_temp(dst_temp, target_.integer_type()),
			target_.make_cnst(offt), target_.integer_type());
		tree::exp *src_exp = target_.make_binop(
			ops::binop::PLUS,
			target_.make_temp(src_temp, target_.integer_type()),
			target_.make_cnst(offt), target_.integer_type());

		dst_exp->ty_ = at->ty_->clone();
		src_exp->ty_ = at->ty_->clone();

		if (types::is_scalar(&dst_exp->ty_)) {
			// scalar, so going to be a simple copy on the next
			// recursion
			dst_exp->ty_ = new types::pointer_ty(dst_exp->ty_);
			dst_exp = target_.make_mem(dst_exp);
			src_exp->ty_ = new types::pointer_ty(src_exp->ty_);
			src_exp = target_.make_mem(src_exp);
		}

		s->children_.push_back(copy(dst_exp, src_exp)->un_nx());
		offt += at->ty_->size();
	}

	return new NX(s);
}

/*
 * lhs and rhs are binop(...), with type struct_ty
 */
utils::ref<exp> translate_visitor::struct_copy(ir::tree::rexp lhs,
					       ir::tree::rexp rhs)
{
	std::cout << "struct_copy(" << lhs->ty_->to_string() << ", "
		  << rhs->ty_->to_string() << ")\n";

	auto st = lhs->ty_.as<types::struct_ty>();
	ASSERT(st && rhs->ty_.as<types::struct_ty>(),
	       "lhs and rhs have to be structs");

	auto s = target_.make_seq({});
	auto dst_base = lhs;
	auto src_base = rhs;

	utils::temp dst_temp;
	utils::temp src_temp;

	s->children_.push_back(target_.make_move(
		target_.make_temp(dst_temp, target_.integer_type()), dst_base));
	s->children_.push_back(target_.make_move(
		target_.make_temp(src_temp, target_.integer_type()), src_base));

	size_t offt = 0;
	for (size_t i = 0; i < st->types_.size(); i++) {
		tree::exp *dst_exp = target_.make_binop(
			ops::binop::PLUS,
			target_.make_temp(dst_temp, target_.integer_type()),
			target_.make_cnst(offt), target_.integer_type());
		tree::exp *src_exp = target_.make_binop(
			ops::binop::PLUS,
			target_.make_temp(src_temp, target_.integer_type()),
			target_.make_cnst(offt), target_.integer_type());

		dst_exp->ty_ = st->types_[i]->clone();
		src_exp->ty_ = st->types_[i]->clone();

		if (types::is_scalar(&dst_exp->ty_)) {
			// scalar, so going to be a simple copy on the next
			// recursion
			dst_exp->ty_ = new types::pointer_ty(dst_exp->ty_);
			dst_exp = target_.make_mem(dst_exp);
			src_exp->ty_ = new types::pointer_ty(src_exp->ty_);
			src_exp = target_.make_mem(src_exp);
		}

		s->children_.push_back(copy(dst_exp, src_exp)->un_nx());
		offt += st->types_[i]->size();
	}

	return new NX(s);
}

/*
 * lhs is a binop(...), with type struct_ty
 * lhs is a binop(...), with type array_ty
 */
utils::ref<exp>
translate_visitor::braceinit_copy(ir::tree::rexp lhs,
				  utils::ref<ir::tree::braceinit> rhs)
{
	if (lhs->ty_.as<types::struct_ty>())
		return braceinit_copy_to_struct(lhs, rhs);
	else if (lhs->ty_.as<types::array_ty>())
		return braceinit_copy_to_array(lhs, rhs);

	UNREACHABLE("Only structs and arrays can make it to this function");
}

utils::ref<exp>
translate_visitor::braceinit_copy_to_array(ir::tree::rexp lhs,
					   utils::ref<ir::tree::braceinit> rhs)
{
	std::cout << "braceinit_copy_to_array(" << lhs->ty_->to_string() << ", "
		  << rhs->ty_->to_string() << ")\n";

	auto bit = rhs->ty_.as<types::braceinit_ty>();
	ASSERT(bit, "rhs has to be a brace init");

	auto at = lhs->ty_.as<types::array_ty>();
	ASSERT(at, "lhs has to be an array");

	auto s = target_.make_seq({});
	auto base = lhs;
	auto exps = rhs->exps();

	utils::temp base_temp;
	s->children_.push_back(target_.make_move(
		target_.make_temp(base_temp, target_.integer_type()), base));

	size_t offt = 0;
	for (size_t i = 0; i < exps.size(); i++) {
		tree::exp *dst_exp = target_.make_binop(
			ops::binop::PLUS,
			target_.make_temp(base_temp, target_.integer_type()),
			target_.make_cnst(offt), target_.integer_type());

		dst_exp->ty_ = at->ty_->clone();

		if (types::is_scalar(&dst_exp->ty_)) {
			// scalar, so going to be a simple copy on the next
			// recursion
			dst_exp->ty_ = new types::pointer_ty(dst_exp->ty_);
			dst_exp = target_.make_mem(dst_exp);
		}

		s->children_.push_back(copy(dst_exp, exps[i])->un_nx());
		offt += at->ty_->size();
	}

	return new NX(s);
}

utils::ref<exp>
translate_visitor::braceinit_copy_to_struct(ir::tree::rexp lhs,
					    utils::ref<ir::tree::braceinit> rhs)
{
	std::cout << "braceinit_copy_to_struct(" << lhs->ty_->to_string()
		  << ", " << rhs->ty_->to_string() << ")\n";

	auto bit = rhs->ty_.as<types::braceinit_ty>();
	ASSERT(bit, "rhs has to be a brace init");

	auto st = lhs->ty_.as<types::struct_ty>();
	ASSERT(st, "lhs has to be a struct");

	auto s = target_.make_seq({});
	auto base = lhs;
	auto exps = rhs->exps();

	utils::temp base_temp;
	s->children_.push_back(target_.make_move(
		target_.make_temp(base_temp, target_.integer_type()), base));

	size_t offt = 0;
	for (size_t i = 0; i < exps.size(); i++) {
		tree::exp *dst_exp = target_.make_binop(
			ops::binop::PLUS,
			target_.make_temp(base_temp, target_.integer_type()),
			target_.make_cnst(offt), target_.integer_type());

		dst_exp->ty_ = st->types_[i]->clone();

		if (types::is_scalar(&dst_exp->ty_)) {
			// scalar, so going to be a simple copy on the next
			// recursion
			dst_exp->ty_ = new types::pointer_ty(dst_exp->ty_);
			dst_exp = target_.make_mem(dst_exp);
		}

		s->children_.push_back(copy(dst_exp, exps[i])->un_nx());
		offt += st->types_[i]->size();
	}

	return new NX(s);
}


utils::ref<exp> translate_visitor::copy(ir::tree::rexp lhs, ir::tree::rexp rhs)
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
	if (types::is_scalar(&lhs->ty_)) {
		return new NX(target_.make_move(lhs, rhs));
	}

	// lhs is a struct
	// rhs is a struct
	if (auto st = rhs->ty_.as<types::struct_ty>())
		return struct_copy(lhs, rhs);
	if (auto brace = rhs.as<tree::braceinit>())
		return braceinit_copy(lhs, brace);
	else if (auto at = lhs->ty_.as<types::array_ty>())
		return array_copy(lhs, rhs);

	UNREACHABLE("Copy not implemented for those types");
}

void translate_visitor::visit_ref(ref &e)
{
	ret_ = new EX(access_to_exp(*e.dec_->access_));
}

void translate_visitor::visit_num(num &e)
{
	ret_ = new EX(target_.make_cnst(e.value_));
}

void translate_visitor::visit_call(call &e)
{
	std::vector<ir::tree::rexp> args;
	for (auto a : e.args_) {
		a->accept(*this);
		args.emplace_back(ret_->un_ex());
	}

	e.f_->accept(*this);
	ir::ir_pretty_printer pir(std::cout);
	ASSERT(e.fty_, "wtf");
	auto *call = target_.make_call(ret_->un_ex(), args, e.fty_);

	ret_ = new EX(call);
}

/*
 * XXX: && and || emit way too many instructions, find a way to optimize them.
 */
void translate_visitor::visit_bin(bin &e)
{
	e.lhs_->accept(*this);
	auto left = ret_->un_ex();
	e.rhs_->accept(*this);
	auto right = ret_->un_ex();

	if (e.op_ == ops::binop::AND) {
		// e1 && e2 is a special case, which gets translated to
		// if (e1 == 0)
		//      0
		// else
		//      e2 != 0
		//
		// e1 == 0, f_label, t_label
		// t_label:
		// result = e2 != 0
		// jmp done_label
		// f_label:
		// result = 0
		// done_label:

		utils::temp result;
		utils::label f_label, t_label, t2_label, done_label;

		utils::ref<cx> cond1 =
			new CX(ops::cmpop::EQ, left, target_.make_cnst(0));
		utils::ref<cx> cond2 =
			new CX(ops::cmpop::NEQ, right, target_.make_cnst(0));

		auto seq = target_.make_seq({
			cond1->un_cx(f_label, t_label),
			target_.make_label(t_label),
			target_.make_move(
				target_.make_temp(result,
						  target_.integer_type()),
				cond2->un_ex()),
			target_.make_jump(target_.make_name(done_label),
					  {done_label}),
			target_.make_label(f_label),
			target_.make_move(
				target_.make_temp(result,
						  target_.integer_type()),
				target_.make_cnst(0)),
			target_.make_label(done_label),
		});

		ret_ = new EX(target_.make_eseq(
			seq,
			target_.make_temp(result, target_.integer_type())));
		return;
	}
	if (e.op_ == ops::binop::OR) {
		/*
		 * e1 || e2 is a special case, which gets translated to
		 * if (e1 == 1)
		 *      1
		 * else
		 *      e1 == 1
		 *
		 * result = e1 == 1
		 * result == 1, done_label, f_label
		 * f_label:
		 * result = e2 == 1
		 * done_label:
		 */

		utils::temp result;
		utils::label f_label, done_label;

		utils::ref<cx> cond1 =
			new CX(ops::cmpop::EQ, left, target_.make_cnst(1));
		utils::ref<cx> cond2 = new CX(
			ops::cmpop::EQ,
			target_.make_temp(result, target_.integer_type()),
			target_.make_cnst(1));
		utils::ref<cx> cond3 =
			new CX(ops::cmpop::EQ, right, target_.make_cnst(1));

		auto seq = target_.make_seq({
			target_.make_move(
				target_.make_temp(result,
						  target_.integer_type()),
				cond1->un_ex()),
			cond2->un_cx(done_label, f_label),
			target_.make_label(f_label),
			target_.make_move(
				target_.make_temp(result,
						  target_.integer_type()),
				cond3->un_ex()),
			target_.make_label(done_label),
		});

		ret_ = new EX(target_.make_eseq(
			seq,
			target_.make_temp(result, target_.integer_type())));
		return;
	}

	/*
	 * + and - are special cases when adding an integer and a pointer,
	 * because the integer must be multiplied by the size of the type
	 * pointed to by the pointer
	 */
	if (e.op_ == ops::binop::PLUS || e.op_ == ops::binop::MINUS) {
		bool should_replace = false;
		if (left->ty_.as<types::pointer_ty>())
			should_replace = types::is_integer(&right->ty_);
		else if (types::is_integer(&left->ty_))
			should_replace =
				right->ty_.as<types::pointer_ty>() != nullptr;

		if (should_replace) {
			if (types::is_integer(&left->ty_)) {
				auto sz = right->ty_.as<types::pointer_ty>()
						  ->pointed_size();
				left = target_.make_binop(
					ops::binop::MULT, target_.make_cnst(sz),
					left, target_.integer_type());
			} else {
				auto sz = left->ty_.as<types::pointer_ty>()
						  ->pointed_size();
				right = target_.make_binop(
					ops::binop::MULT, target_.make_cnst(sz),
					right, target_.integer_type());
			}
		}
	}

	ret_ = new EX(
		target_.make_binop(e.op_, left, right, left->ty_->clone()));
}

void translate_visitor::visit_unary(unary &e)
{
	e.e_->accept(*this);
	ret_ = new EX(
		target_.make_unaryop(e.op_, ret_->un_ex(), e.ty_->clone()));
}

void translate_visitor::visit_cast(cast &e)
{
	e.e_->accept(*this);
	auto c = ret_->un_ex();
	c->ty_ = e.ty_;
	ret_ = new EX(c);
}

void translate_visitor::visit_cmp(cmp &e)
{
	e.lhs_->accept(*this);
	auto left = ret_;
	e.rhs_->accept(*this);
	auto right = ret_;

	ret_ = new CX(e.op_, left->un_ex(), right->un_ex());
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
	for (auto s : s.body_) {
		s->accept(*this);
		stms.push_back(ret_->un_nx());
	}
	auto body = target_.make_seq(stms);

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

	ret_ = new NX(target_.make_seq({
		init->un_nx(),
		target_.make_label(cond_lbl),
		cond->un_cx(body_lbl, end_lbl),
		target_.make_label(body_lbl),
		body,
		action->un_nx(),
		target_.make_jump(target_.make_name(cond_lbl), {cond_lbl}),
		target_.make_label(end_lbl),
	}));
}

void translate_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);
	auto cond = ret_;

	std::vector<ir::tree::rstm> istms;
	for (auto s : s.ibody_) {
		s->accept(*this);
		istms.push_back(ret_->un_nx());
	}
	auto ibody = target_.make_seq(istms);

	std::vector<ir::tree::rstm> estms;
	for (auto s : s.ebody_) {
		s->accept(*this);
		estms.push_back(ret_->un_nx());
	}
	auto ebody = target_.make_seq(estms);

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

	ret_ = new NX(target_.make_seq({
		cond->un_cx(i_lbl, e_lbl),
		target_.make_label(i_lbl),
		ibody,
		target_.make_jump(target_.make_name(end_lbl), {end_lbl}),
		target_.make_label(e_lbl),
		ebody,
		target_.make_label(end_lbl),
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

void translate_visitor::visit_inline_asm(inline_asm &s)
{
	std::vector<utils::temp> reg_in;
	std::vector<utils::temp> reg_out;
	std::vector<utils::temp> reg_clob;

	auto pre = target_.make_seq({});
	for (auto &rm : s.reg_in_) {
		auto reg = target_.repr_to_register(rm.regstr_);
		reg_in.push_back(reg);

		rm.e_->accept(*this);
		pre->children_.push_back(target_.make_move(
			target_.make_temp(reg, target_.integer_type()),
			ret_->un_ex()));
	}

	auto post = target_.make_seq({});
	for (auto &rm : s.reg_out_) {
		auto reg = target_.repr_to_register(rm.regstr_);
		reg_out.push_back(reg);

		rm.e_->accept(*this);
		post->children_.push_back(target_.make_move(
			ret_->un_ex(),
			target_.make_temp(reg, target_.integer_type())));
	}

	for (auto &rm : s.reg_clob_)
		reg_clob.push_back(target_.repr_to_register(rm));

	ret_ = new NX(target_.make_seq(
		{pre,
		 target_.make_asm_block(s.lines_, reg_in, reg_out, reg_clob),
		 post}));
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
		ret_ = new NX(target_.make_jump(target_.make_name(ret_lbl_),
						{ret_lbl_}));
		return;
	}

	auto fty = s.fdec_->type_.as<types::fun_ty>();

	s.e_->accept(*this);
	auto lhs = ret_->un_ex();
	ret_ = new NX(target_.make_seq({
		target_.make_move(target_.make_temp(target_.rv(), fty->ret_ty_),
				  lhs),
		target_.make_jump(target_.make_name(ret_lbl_), {ret_lbl_}),
	}));
}

void translate_visitor::visit_str_lit(str_lit &e)
{
	utils::label lab = unique_label("str_lit");

	ret_ = new EX(target_.make_name(lab, target_.string_type()));

	str_lits_.emplace(lab, e);
}

void translate_visitor::visit_decs(decs &s)
{
	default_visitor::visit_decs(s);

	if (init_funs_.size() == 0)
		return;

	auto body = target_.make_seq(init_funs_);
	utils::label ret_lbl = unique_label("init_vars_ret");
	auto frame =
		target_.make_frame(unique_label("init_vars"), {}, {}, false);
	init_fun_ = new mach::fun_fragment(
		frame->proc_entry_exit_1(body, ret_lbl), frame, ret_lbl,
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
	for (auto stm : s.body_) {
		stm->accept(*this);
		stms.push_back(ret_->un_nx());
	}
	auto body = target_.make_seq(stms);

	funs_.emplace_back(s.frame_->proc_entry_exit_1(body, ret_lbl_),
			   s.frame_, ret_lbl_,
			   unique_label(s.name_.get() + "_epi"));

	ret_lbl_.leave();
}

void translate_visitor::visit_deref(deref &e)
{
	e.e_->accept(*this);
	ret_ = new EX(target_.make_mem(ret_->un_ex()));
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
		ret_ = new EX(r->e());
	else {
		ret->ty_ = new types::pointer_ty(ret->ty_);
		ret_ = new EX(ret);
	}
}

/*
 * e.e_ is a binop(...), which points to the struct
 * if the member is a struct, then don't emit the mem node
 */
utils::ref<exp> translate_visitor::struct_access(ir::tree::rexp lhs,
						 const symbol &member)
{
	auto st = lhs->ty_.as<types::struct_ty>();
	if (!st) {
		// the struct type can be embedded in a pointer type, in the
		// case of arrow accesses.
		auto pt = lhs->ty_.as<types::pointer_ty>();
		st = pt->ty_.as<types::struct_ty>();
	}
	auto mem_ty = st->member_ty(member);
	size_t offt = st->member_offset(member);

	ir::tree::exp *dst =
		target_.make_binop(ops::binop::PLUS, lhs,
				   target_.make_cnst(offt), lhs->ty_->clone());
	dst->ty_ = mem_ty->clone();

	if (types::is_scalar(&dst->ty_)) {
		// the member is a scalar, so return the value and not the
		// address
		dst->ty_ = new types::pointer_ty(dst->ty_);
		dst = target_.make_mem(dst);
	}

	return new EX(dst);
}

void translate_visitor::visit_memberaccess(memberaccess &e)
{
	e.e_->accept(*this);
	ret_ = struct_access(ret_->un_ex(), e.member_);
}

/*
 * The only difference between pointers to structs and structs is their
 * type, but the value of e.e_ is going to be a pointer in both cases
 */
void translate_visitor::visit_arrowaccess(arrowaccess &e)
{
	e.e_->accept(*this);
	ret_ = struct_access(ret_->un_ex(), e.member_);
}

void translate_visitor::visit_braceinit(braceinit &e)
{
	auto bi = target_.make_braceinit(e.ty_, {});

	for (auto &c : e.exps_) {
		c->accept(*this);
		bi->children_.push_back(ret_->un_ex());
	}

	ret_ = new EX(bi);
}

void translate_visitor::visit_subscript(subscript &e)
{
	e.base_->accept(*this);
	auto base = ret_->un_ex();
	e.index_->accept(*this);
	auto index = ret_->un_ex();

	ret_ = new EX(target_.make_mem(target_.make_binop(
		ops::binop::PLUS, base,
		target_.make_binop(ops::binop::MULT, index,
				   target_.make_cnst(e.ty_->size()),
				   target_.integer_type()),
		base->ty_->clone())));
}
} // namespace frontend::translate
