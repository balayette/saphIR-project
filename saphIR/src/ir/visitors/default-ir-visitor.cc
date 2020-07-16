#include "ir/visitors/default-ir-visitor.hh"
namespace ir
{
void default_ir_visitor::visit_cnst(tree::cnst &) {}

void default_ir_visitor::visit_braceinit(tree::braceinit &bi)
{
	for (auto &c : bi.children_)
		c->accept(*this);
}

void default_ir_visitor::visit_name(tree::name &) {}

void default_ir_visitor::visit_temp(tree::temp &) {}

void default_ir_visitor::visit_binop(tree::binop &n)
{
	n.lhs()->accept(*this);
	n.rhs()->accept(*this);
}

void default_ir_visitor::visit_unaryop(tree::unaryop &n)
{
	n.e()->accept(*this);
}

void default_ir_visitor::visit_mem(tree::mem &n) { n.e()->accept(*this); }

void default_ir_visitor::visit_call(tree::call &n)
{
	n.f()->accept(*this);
	for (auto a : n.args())
		a->accept(*this);
}

void default_ir_visitor::visit_eseq(tree::eseq &n)
{
	n.lhs()->accept(*this);
	n.rhs()->accept(*this);
}

void default_ir_visitor::visit_move(tree::move &n)
{
	n.lhs()->accept(*this);
	n.rhs()->accept(*this);
}

void default_ir_visitor::visit_sexp(tree::sexp &n) { n.e()->accept(*this); }

void default_ir_visitor::visit_jump(tree::jump &n) { n.dest()->accept(*this); }

void default_ir_visitor::visit_cjump(tree::cjump &n)
{
	n.lhs()->accept(*this);
	n.lhs()->accept(*this);
}

void default_ir_visitor::visit_seq(tree::seq &n)
{
	for (auto s : n.body())
		s->accept(*this);
}

void default_ir_visitor::visit_label(tree::label &) {}

void default_ir_visitor::visit_asm_block(tree::asm_block &) {}
} // namespace ir
