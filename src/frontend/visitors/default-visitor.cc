#include "frontend/visitors/default-visitor.hh"
namespace frontend
{
void default_visitor::visit_decs(decs &s)
{
	for (auto d : s.decs_)
		d->accept(*this);
}

void default_visitor::visit_memberdec(memberdec &) {}

void default_visitor::visit_structdec(structdec &s)
{
	for (auto mem : s.members_)
		mem->accept(*this);
}

void default_visitor::visit_globaldec(globaldec &s) { s.rhs_->accept(*this); }

void default_visitor::visit_locdec(locdec &s)
{
	if (s.rhs_)
		s.rhs_->accept(*this);
}

void default_visitor::visit_funprotodec(funprotodec &s)
{
	for (auto arg : s.args_)
		arg->accept(*this);
}

void default_visitor::visit_fundec(fundec &s)
{
	for (auto arg : s.args_)
		arg->accept(*this);
	for (auto b : s.body_)
		b->accept(*this);
}

void default_visitor::visit_sexp(sexp &s) { s.e_->accept(*this); }

void default_visitor::visit_ret(ret &s)
{
	if (s.e_ != nullptr)
		s.e_->accept(*this);
}

void default_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);
	for (auto i : s.ibody_)
		i->accept(*this);
	for (auto e : s.ebody_)
		e->accept(*this);
}

void default_visitor::visit_forstmt(forstmt &s)
{
	s.init_->accept(*this);
	s.cond_->accept(*this);
	s.action_->accept(*this);

	for (auto b : s.body_)
		b->accept(*this);
}

void default_visitor::visit_ass(ass &s)
{
	s.lhs_->accept(*this);
	s.rhs_->accept(*this);
}

void default_visitor::visit_paren(paren &e) { e.e_->accept(*this); }

void default_visitor::visit_braceinit(braceinit &e)
{
	for (auto e : e.exps_)
		e->accept(*this);
}

void default_visitor::visit_bin(bin &e)
{
	e.lhs_->accept(*this);
	e.rhs_->accept(*this);
}

void default_visitor::visit_unary(unary &e)
{
        e.e_->accept(*this);
}

void default_visitor::visit_cmp(cmp &e)
{
	e.lhs_->accept(*this);
	e.rhs_->accept(*this);
}

void default_visitor::visit_num(num &) {}

void default_visitor::visit_ref(ref &) {}

void default_visitor::visit_deref(deref &e) { e.e_->accept(*this); }

void default_visitor::visit_addrof(addrof &e) { e.e_->accept(*this); }

void default_visitor::visit_call(call &e)
{
	for (auto a : e.args_)
		a->accept(*this);
}

void default_visitor::visit_str_lit(str_lit &) {}

void default_visitor::visit_memberaccess(memberaccess &e)
{
	e.e_->accept(*this);
}

void default_visitor::visit_arrowaccess(arrowaccess &e) { e.e_->accept(*this); }

void default_visitor::visit_subscript(subscript &e)
{
	e.base_->accept(*this);
	e.index_->accept(*this);
}
} // namespace frontend
