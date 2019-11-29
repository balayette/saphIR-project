#include "translate.hh"
#include "temp.hh"
#include <iostream>
#include "exp.hh"
#include "ir.hh"
#include "ir-pretty-printer.hh"

#define TRANS_DEBUG 1

namespace frontend::translate
{

using namespace backend;

cx::cx(frontend::cmpop op, tree::rexp l, tree::rexp r) : op_(op), l_(l), r_(r)
{
#if TRANS_DEBUG
	backend::ir_pretty_printer p(std::cout);
	std::cout << "cx: " << cmpop_to_string(op) << '\n';
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
	return new tree::cjump(frontend::cmpop::NEQ, e_, new tree::cnst(0), t,
			       f);
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
} // namespace frontend::translate
