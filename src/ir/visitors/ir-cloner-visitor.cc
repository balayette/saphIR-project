#include "ir/visitors/ir-cloner-visitor.hh"
#include "utils/assert.hh"

#define REC(C)                                                                 \
	do {                                                                   \
		auto tmp = curr_;                                              \
		curr_ = (C);                                                   \
		(C)->accept(*this);                                            \
		curr_ = tmp;                                                   \
	} while (0);

namespace ir
{
void ir_cloner_visitor::visit_braceinit(tree::braceinit &n)
{
	utils::ref<types::ty> nty = n.ty_->clone();

	std::vector<tree::rexp> nchildren;
	for (auto &e : n.exps()) {
		auto ne = recurse(e);
		nchildren.push_back(ne);
	}

	ret_ = new tree::braceinit(nty, nchildren);
}

void ir_cloner_visitor::visit_cnst(tree::cnst &n)
{
	auto c = new tree::cnst(n.value_);
	c->ty_ = n.ty_->clone();
	ret_ = c;
}

void ir_cloner_visitor::visit_name(tree::name &n)
{
	if (n.ty_)
		ret_ = new tree::name(n.label_, n.ty_->clone());
	else
		ret_ = new tree::name(n.label_);
}

void ir_cloner_visitor::visit_temp(tree::temp &n)
{
	ret_ = new tree::temp(n.temp_, n.ty_->clone());
}

void ir_cloner_visitor::visit_binop(tree::binop &n)
{
	auto b = new tree::binop(n.op_, recurse(n.lhs()), recurse(n.rhs()));
	b->ty_ = n.ty_->clone();

	ret_ = b;
}

void ir_cloner_visitor::visit_mem(tree::mem &n)
{
	auto e = recurse(n.e());
	e->ty_ = e->ty_->clone();

	ret_ = new tree::mem(e);
}

void ir_cloner_visitor::visit_call(tree::call &n)
{
	std::vector<tree::rexp> nargs;

	for (auto e : n.args())
		nargs.push_back(recurse(e));

	ret_ = new tree::call(recurse(n.name()), nargs, n.fun_ty_->clone());
}

void ir_cloner_visitor::visit_eseq(tree::eseq &n)
{
	ret_ = new tree::eseq(recurse(n.lhs()), recurse(n.rhs()));
}

void ir_cloner_visitor::visit_move(tree::move &n)
{
	ret_ = new tree::move(recurse(n.lhs()), recurse(n.rhs()));
}

void ir_cloner_visitor::visit_sexp(tree::sexp &n)
{
	ret_ = new tree::sexp(recurse(n.e()));
}

void ir_cloner_visitor::visit_jump(tree::jump &n)
{
	ret_ = new tree::jump(recurse(n.dest()), n.avlbl_dests_);
}

void ir_cloner_visitor::visit_cjump(tree::cjump &n)
{
	ret_ = new tree::cjump(n.op_, recurse(n.lhs()), recurse(n.rhs()),
			       n.ltrue_, n.lfalse_);
}

void ir_cloner_visitor::visit_seq(tree::seq &n)
{
	std::vector<tree::rstm> nbody;

	for (auto e : n.body())
		nbody.push_back(recurse(e));

	ret_ = new tree::seq(nbody);
}

void ir_cloner_visitor::visit_label(tree::label &n)
{
	ret_ = new tree::label(n.name_);
}
} // namespace ir
