#include <iostream>
#include "ir/visitors/ir-pretty-printer.hh"
#include "ir/canon/linearize.hh"
#include "mach/target.hh"

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

	auto &target = stm1->target();
	utils::ref<tree::seq> ret = target.make_seq({});

	if (stm1.as<tree::seq>())
		ret->children().insert(ret->children().end(),
				       stm1->children().begin(),
				       stm1->children().end());
	else
		ret->append(stm1);

	if (stm2.as<tree::seq>())
		ret->children().insert(ret->children().end(),
				       stm2->children().begin(),
				       stm2->children().end());
	else
		ret->append(stm2);

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


	auto &target = stm->target();
	return target.make_eseq(stm, exp);
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
	auto &target = tree->target();

	std::vector<tree::rnode> &children = tree->children();
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
				bigseq = make_stm(
					bigseq, target.make_sexp(eseq->rhs()));
				// nop statement
				*ichild = target.make_cnst(0);
			} else {
				bigseq = make_stm(bigseq, eseq->lhs());
				*ichild = eseq->rhs();
			}
		}

		if (auto call = ichild->as<tree::call>()) {
			if (!valid_call(tree, call)) {
				utils::temp tmp;
				bigseq = make_stm(
					bigseq, target.make_move(
							target.make_temp(
								tmp, call->ty_),
							call));
				*ichild = target.make_temp(tmp, call->ty_);
			}
		}

		auto mv = tree.as<tree::move>();
		if (mv && ichild == children.begin()) {
			if (auto mem = ichild->as<tree::mem>()) {
				/*
				 * Instead of doing like Appel and storing
				 * the address in a temporary, store the value
				 * in a temp. This makes codegen optimization
				 * of addressing modes easier.
				 */
				utils::temp tmp;
				bigseq = make_stm(
					bigseq,
					target.make_move(
						target.make_temp(
							tmp, mv->rhs()->ty_),
						mv->rhs()));

				mv->children()[1] =
					target.make_temp(tmp, mv->rhs()->ty_);
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
	std::vector<tree::rnode> &children = tree->children();

	for (tree::rnode &t : children) {
		if (auto seq = t.as<tree::seq>())
			res.insert(res.end(), seq->children().begin(),
				   seq->children().end());
		else if (!is_nop(t))
			res.emplace_back(t);
	}

	children = res;

	return tree;
}

tree::rnode canon(tree::rnode tree)
{
	for (auto &c : tree->children())
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
