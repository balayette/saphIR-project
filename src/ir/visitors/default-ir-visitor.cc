#include "ir/visitors/default-ir-visitor.hh"
namespace backend
{
void default_ir_visitor::visit_cnst(tree::cnst &) {}

void default_ir_visitor::visit_name(tree::name &) {}

void default_ir_visitor::visit_temp(tree::temp &) {}

void default_ir_visitor::visit_binop(tree::binop &n)
{
	n.lhs_->accept(*this);
	n.rhs_->accept(*this);
}

void default_ir_visitor::visit_mem(tree::mem &n) { n.e_->accept(*this); }

void default_ir_visitor::visit_call(tree::call &n)
{
	for (auto a : n.args_)
		a->accept(*this);
}

void default_ir_visitor::visit_eseq(tree::eseq &n)
{
	n.lhs_->accept(*this);
	n.rhs_->accept(*this);
}

void default_ir_visitor::visit_move(tree::move &n)
{
	n.lhs_->accept(*this);
	n.rhs_->accept(*this);
}

void default_ir_visitor::visit_sexp(tree::sexp &n) { n.e_->accept(*this); }

void default_ir_visitor::visit_jump(tree::jump &n) { n.dest_->accept(*this); }

void default_ir_visitor::visit_cjump(tree::cjump &n)
{
	n.lhs_->accept(*this);
	n.lhs_->accept(*this);
}

void default_ir_visitor::visit_seq(tree::seq &n)
{
	for (auto s : n.body_)
		s->accept(*this);
}

void default_ir_visitor::visit_label(tree::label &) {}
} // namespace backend
