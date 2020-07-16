#include <iostream>
#include "ir/visitors/ir-pretty-printer.hh"
#include "ir/canon/linearize.hh"

namespace ir
{
bool is_nop(tree::rnode stm)
{
	if (auto sexp = stm.as<tree::sexp>())
		return sexp->e()->kind() == tree::tree_kind::cnst;
	return false;
}

tree::rstm make_stm(tree::rstm stm1, tree::rstm stm2)
{
	if (!stm1 || is_nop(stm1))
		return stm2;
	if (!stm2 || is_nop(stm2))
		return stm1;

	utils::ref<tree::seq> ret = new tree::seq({});

	if (stm1.as<tree::seq>())
		ret->children_.insert(ret->children_.end(),
				      stm1->children_.begin(),
				      stm1->children_.end());
	else
		ret->children_.emplace_back(stm1);

	if (stm2.as<tree::seq>())
		ret->children_.insert(ret->children_.end(),
				      stm2->children_.begin(),
				      stm2->children_.end());
	else
		ret->children_.emplace_back(stm2);

	return ret;
}

tree::rexp make_eseq(tree::rstm stm, tree::rexp exp)
{
	if (!stm || is_nop(stm))
		return exp;

	if (auto e = exp.as<tree::eseq>()) {
		stm = make_stm(stm, e->lhs());
		exp = e->rhs();
	}


	return new tree::eseq(stm, exp);
}

bool valid_call(tree::rnode tree, utils::ref<tree::call> call)
{
	if (tree.as<tree::sexp>())
		return true;

	auto mv = tree.as<tree::move>();
	if (!mv)
		return false;

	if (!mv->lhs().as<tree::temp>())
		return false;

	if (call != mv->rhs())
		return false;

	return true;
}

tree::rnode canon_default(tree::rnode &tree)
{
	tree::rstm bigseq;

	std::vector<tree::rnode> &children = tree->children_;
	for (auto ichild = children.begin(); ichild != children.end();
	     ichild++) {
		if (auto eseq = ichild->as<tree::eseq>()) {
			if (auto binop = tree.as<tree::binop>()) {
				bigseq = make_stm(bigseq, eseq->lhs());
				*ichild = eseq->rhs();
			} else if (auto call = tree.as<tree::call>()) {
				bigseq = make_stm(bigseq, eseq->lhs());
				*ichild = eseq->rhs();
			} else if (auto sexp = tree.as<tree::sexp>()) {
				bigseq = make_stm(bigseq, eseq->lhs());
				bigseq = make_stm(bigseq,
						  new tree::sexp(eseq->rhs()));
				// nop statement
				*ichild = new tree::cnst(0);
			} else {
				bigseq = make_stm(bigseq, eseq->lhs());
				*ichild = eseq->rhs();
			}
		}

		if (auto call = ichild->as<tree::call>()) {
			if (!valid_call(tree, call)) {
				utils::temp tmp;
				bigseq = make_stm(
					bigseq,
					new tree::move(
						new tree::temp(tmp, call->ty_),
						call));
				*ichild = new tree::temp(tmp, call->ty_);
			}
		}

		auto mv = tree.as<tree::move>();
		if (mv && ichild == children.begin()) {
			if (auto mem = ichild->as<tree::mem>()) {
				utils::temp tmp;
				bigseq = make_stm(
					bigseq,
					new tree::move(
						new tree::temp(tmp,
							       mem->e()->ty_),
						mem->e()));

				*(mv->lhs()) = tree::mem(
					new tree::temp(tmp, mem->e()->ty_));
			}
		}
	}

	ir_pretty_printer pp(std::cout);

	if (auto exp = tree.as<tree::exp>())
		return make_eseq(bigseq, exp);
	return make_stm(bigseq, tree.as<tree::stm>());
}

tree::rnode canon_eseq(utils::ref<tree::eseq> tree)
{
	return make_eseq(tree->lhs(), tree->rhs());
}

tree::rnode canon_seq(utils::ref<tree::seq> tree)
{
	std::vector<tree::rnode> res;
	std::vector<tree::rnode> &children = tree->children_;

	for (tree::rnode &t : children) {
		if (auto seq = t.as<tree::seq>())
			res.insert(res.end(), seq->children_.begin(),
				   seq->children_.end());
		else if (!is_nop(t))
			res.emplace_back(t);
	}

	children = res;

	return tree;
}

tree::rnode canon(tree::rnode tree)
{
	for (auto &c : tree->children_)
		c = canon(c);

	if (auto t = tree.as<tree::eseq>())
		tree = canon_eseq(t);
	if (auto t = tree.as<tree::seq>())
		tree = canon_seq(t);
	else
		tree = canon_default(tree);

	return tree;
}
} // namespace ir
