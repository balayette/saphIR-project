#pragma once

#include "default-ir-visitor.hh"
#include "ir.hh"

namespace backend
{
class ir_pretty_printer : public default_ir_visitor
{
      public:
	ir_pretty_printer(std::ostream &os) : os_(os), lvl_(0) {}
	virtual void visit_cnst(tree::cnst &n) override
	{
		indent() << "(const " << n.value_ << ")\n";
	}
	virtual void visit_name(tree::name &n) override
	{
		indent() << "(name " << n.label_ << ")\n";
	}
	virtual void visit_temp(tree::temp &n) override
	{
		indent() << "(temp " << n.temp_ << ")\n";
	}
	virtual void visit_binop(tree::binop &n) override
	{
		indent() << "(binop " << frontend::binop_to_string(n.op_)
			 << "\n";
		lvl_++;
		n.lhs_->accept(*this);
		n.rhs_->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_mem(tree::mem &n) override
	{
		indent() << "(mem\n";
		lvl_++;
		n.e_->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_call(tree::call &n) override
	{
		indent() << "(call\n";
		lvl_++;
		n.name_->accept(*this);
		for (auto a : n.args_)
			a->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_eseq(tree::eseq &n) override
	{
		indent() << "(eseq\n";
		lvl_++;
		n.lhs_->accept(*this);
		n.rhs_->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_move(tree::move &n) override
	{
		indent() << "(mov\n";
		lvl_++;
		n.lhs_->accept(*this);
		n.rhs_->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_sexp(tree::sexp &n) override
	{
		indent() << "(sexp\n";
		lvl_++;
		n.e_->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_jump(tree::jump &n) override
	{
		indent() << "(jump\n";
		lvl_++;
		n.dest_->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_cjump(tree::cjump &n) override
	{
		indent() << "(cjump " << frontend::cmpop_to_string(n.op_)
			 << "\n";
		lvl_++;
		n.lhs_->accept(*this);
		n.rhs_->accept(*this);
		indent() << "t => " << n.ltrue_ << '\n';
		indent() << "f => " << n.lfalse_ << '\n';
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_seq(tree::seq &n) override
	{
		indent() << "(seq\n";
		lvl_++;
		for (auto s : n.body_)
			s->accept(*this);
		lvl_--;
		indent() << ")\n";
	}
	virtual void visit_label(tree::label &n) override
	{
		indent() << "(label " << n.name_ << ")\n";
	}

      private:
	std::ostream &indent()
	{
		for (unsigned i = 0; i < lvl_; i++)
			os_ << "    ";
		return os_;
	}
	std::ostream &os_;
	unsigned lvl_;
};
} // namespace backend
