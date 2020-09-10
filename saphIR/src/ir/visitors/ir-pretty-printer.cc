#include "ir/visitors/ir-pretty-printer.hh"
namespace ir
{
ir_pretty_printer::ir_pretty_printer(std::ostream &os) : os_(os), lvl_(0) {}

void ir_pretty_printer::visit_cnst(tree::cnst &n)
{
	indent() << "(const" << n.ty_->assem_size() << " " << (int64_t)n.value_
		 << ")\n";
}

void ir_pretty_printer::visit_braceinit(tree::braceinit &n)
{
	indent() << "(braceinit\n";
	lvl_++;
	for (auto &c : n.children())
		c->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_name(tree::name &n)
{
	indent() << "(name " << n.label_ << ")\n";
}

void ir_pretty_printer::visit_temp(tree::temp &n)
{
	indent() << "(temp " << n.temp_ << "_" << n.ty_->assem_size() << ")\n";
}

void ir_pretty_printer::visit_binop(tree::binop &n)
{
	indent() << "(binop " << ops::binop_to_string(n.op_) << "\n";
	lvl_++;
	n.lhs()->accept(*this);
	n.rhs()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_unaryop(tree::unaryop &n)
{
	indent() << "(unaryop " << ops::unaryop_to_string(n.op_) << "\n";
	lvl_++;
	n.e()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_mem(tree::mem &n)
{
	indent() << "(mem" << n.ty_->assem_size() << '\n';
	lvl_++;
	n.e()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_call(tree::call &n)
{
	indent() << "(call\n";
	lvl_++;
	n.f()->accept(*this);
	for (auto a : n.args())
		a->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_eseq(tree::eseq &n)
{
	indent() << "(eseq\n";
	lvl_++;
	n.lhs()->accept(*this);
	n.rhs()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_sext(tree::sext &n)
{
	indent() << "(sext" << n.ty_->assem_size() << "\n";
	lvl_++;
	n.e()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_zext(tree::zext &n)
{
	indent() << "(zext" << n.ty_->assem_size() << "\n";
	lvl_++;
	n.e()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_move(tree::move &n)
{
	indent() << "(mov\n";
	lvl_++;
	n.lhs()->accept(*this);
	n.rhs()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_sexp(tree::sexp &n)
{
	indent() << "(sexp\n";
	lvl_++;
	n.e()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_jump(tree::jump &n)
{
	indent() << "(jump\n";
	lvl_++;
	n.dest()->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_cjump(tree::cjump &n)
{
	indent() << "(cjump " << ops::cmpop_to_string(n.op_) << "\n";
	lvl_++;
	n.lhs()->accept(*this);
	n.rhs()->accept(*this);
	indent() << "t => " << n.ltrue_ << '\n';
	indent() << "f => " << n.lfalse_ << '\n';
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_seq(tree::seq &n)
{
	indent() << "(seq\n";
	lvl_++;
	for (auto s : n.body())
		s->accept(*this);
	lvl_--;
	indent() << ")\n";
}

void ir_pretty_printer::visit_label(tree::label &n)
{
	indent() << "(label " << n.name_ << ")\n";
}

void ir_pretty_printer::visit_asm_block(tree::asm_block &n)
{
	indent() << "(asm_block\n";
	lvl_++;
	for (size_t i = 0; i < n.lines_.size(); i++)
		indent() << n.lines_[i] << '\n';
	lvl_--;
	indent() << ")\n";
}

std::ostream &ir_pretty_printer::indent()
{
	for (unsigned i = 0; i < lvl_; i++)
		os_ << "    ";
	return os_;
}
} // namespace ir
