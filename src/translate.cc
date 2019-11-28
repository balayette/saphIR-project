#include "translate.hh"
#include "temp.hh"
#include <iostream>
#include "exp.hh"

namespace frontend::translate
{
cx::cx(frontend::cmpop op, backend::tree::exp *l, backend::tree::exp *r)
    : op_(op), l_(l), r_(r)
{
}

backend::tree::exp *cx::un_ex()
{
	auto ret = ::temp::temp();
	auto t_lbl = ::temp::label();
	auto f_lbl = ::temp::label();
	auto e_lbl = ::temp::label();

	auto *lt = new backend::tree::label(t_lbl);
	auto *lf = new backend::tree::label(f_lbl);
	auto *le = new backend::tree::label(e_lbl);

	auto *je = new backend::tree::jump(new backend::tree::name(e_lbl),
					   {e_lbl});
	auto *cj = new backend::tree::cjump(op_, l_, r_, t_lbl, f_lbl);

	auto *movt = new backend::tree::move(new backend::tree::temp(ret),
					     new backend::tree::cnst(1));
	auto *movf = new backend::tree::move(new backend::tree::temp(ret),
					     new backend::tree::cnst(0));

	auto *body = new backend::tree::seq({cj, lt, movt, je, lf, movf, le});

	backend::tree::exp *value = new backend::tree::temp(ret);

	return new backend::tree::eseq(body, value);
}

backend::tree::stm *cx::un_nx()
{
	return new backend::tree::seq(
		{new backend::tree::sexp(l_), new backend::tree::sexp(r_)});
}

backend::tree::stm *cx::un_cx(const temp::label &t, const temp::label &f)
{
	return new backend::tree::cjump(op_, l_, r_, t, f);
}

backend::tree::exp *ex::un_ex() { return e_; }
backend::tree::stm *ex::un_nx() { return new backend::tree::sexp(e_); }
backend::tree::stm *ex::un_cx(const temp::label &t, const temp::label &f)
{
	return new backend::tree::cjump(frontend::cmpop::NEQ, e_,
					new backend::tree::cnst(0), t, f);
}

backend::tree::exp *nx::un_ex()
{
	std::cerr << "Can't un_ex an nx\n";
	std::exit(5);
}

backend::tree::stm *nx::un_nx() { return s_; }

backend::tree::stm *nx::un_cx(const temp::label &, const temp::label &)
{
	std::cerr << "Can't un_cx an nx\n";
	std::exit(5);
}
} // namespace frontend::translate
