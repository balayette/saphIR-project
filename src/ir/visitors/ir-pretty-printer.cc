#include "ir/visitors/ir-pretty-printer.hh"
namespace backend
{
ir_pretty_printer::ir_pretty_printer(std::ostream &os) : os_(os), lvl_(0) {}

void ir_pretty_printer::visit_cnst(tree::cnst &n)
{
	indent() << "(const " << n.value_ << ")\n";
}

void ir_pretty_printer::visit_name(tree::name &n)
{
	indent() << "(name " << n.label_ << ")\n";
}

void ir_pretty_printer::visit_temp(tree::temp &n)
{
	indent() << "(temp " << n.temp_ << ")\n";
}

void ir_pretty_printer::visit_binop(tree::binop &n)
{
	indent() << "(binop " << ops::binop_to_string(n.op_) << "\n";
	lvl_++;
	n.lhs_->accept(*this);
	n.rhs_->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_mem(tree::mem &n)
{
	indent() << "(mem\n";
	lvl_++;
	n.e_->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_call(tree::call &n)
{
	indent() << "(call\n";
	lvl_++;
	n.name_->accept(*this);
	for (auto a : n.args_)
		a->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_eseq(tree::eseq &n)
{
	indent() << "(eseq\n";
	lvl_++;
	n.lhs_->accept(*this);
	n.rhs_->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_move(tree::move &n)
{
	indent() << "(mov\n";
	lvl_++;
	n.lhs_->accept(*this);
	n.rhs_->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_sexp(tree::sexp &n)
{
	indent() << "(sexp\n";
	lvl_++;
	n.e_->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_jump(tree::jump &n)
{
	indent() << "(jump\n";
	lvl_++;
	n.dest_->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_cjump(tree::cjump &n)
{
	indent() << "(cjump " << ops::cmpop_to_string(n.op_) << "\n";
	lvl_++;
	n.lhs_->accept(*this);
	n.rhs_->accept(*this);
	indent() << "t => " << n.ltrue_ << '\n';
	indent() << "f => " << n.lfalse_ << '\n';
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_seq(tree::seq &n)
{
	indent() << "(seq\n";
	lvl_++;
	for (auto s : n.body_)
		s->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_label(tree::label &n)
{
	indent() << "(label " << n.name_ << ")\n";
}

std::ostream &ir_pretty_printer::indent()
{
	for (unsigned i = 0; i < lvl_; i++)
		os_ << "    ";
	return os_;
}
} // namespace backend
