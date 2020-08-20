#include "ir/ir.hh"
#include "mach/target.hh"

namespace ir::tree
{
cnst::cnst(mach::target &target, uint64_t value)
    : exp(target, target.integer_type()), value_(value)
{
}

cnst::cnst(mach::target &target, uint64_t value, types::signedness signedness,
	   size_t sz)
    : exp(target, target.integer_type(signedness, sz)), value_(value)
{
}

meta_cx::meta_cx(mach::target &target, ops::cmpop op, tree::rexp l,
		 tree::rexp r)
    : meta_exp(target), op_(op), l_(l), r_(r)
{
}

tree::rexp meta_cx::un_ex()
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

tree::rstm meta_cx::un_nx()
{
	return target_.make_seq({target_.make_sexp(l_), target_.make_sexp(r_)});
}

tree::rstm meta_cx::un_cx(const utils::label &t, const utils::label &f)
{
	return target_.make_cjump(op_, l_, r_, t, f);
}

meta_ex::meta_ex(mach::target &target, ir::tree::rexp e)
    : meta_exp(target), e_(e)
{
}

tree::rexp meta_ex::un_ex() { return e_; }

tree::rstm meta_ex::un_nx() { return target_.make_sexp(e_); }

tree::rstm meta_ex::un_cx(const utils::label &t, const utils::label &f)
{
	return target_.make_cjump(ops::cmpop::NEQ, e_, target_.make_cnst(0), t,
				  f);
}

meta_nx::meta_nx(mach::target &target, ir::tree::rstm s)
    : meta_exp(target), s_(s)
{
}

tree::rexp meta_nx::un_ex() { ASSERT(false, "Can't un_ex an nx"); }

tree::rstm meta_nx::un_nx() { return s_; }

tree::rstm meta_nx::un_cx(const utils::label &, const utils::label &)
{
	ASSERT(false, "Can't un_cx an nx");
}

} // namespace ir::tree
