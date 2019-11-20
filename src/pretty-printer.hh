#pragma once
#include "default-visitor.hh"
#include "types.hh"
#include <iostream>
#include <string>

namespace frontend
{
class pretty_printer : public default_visitor
{
      public:
	pretty_printer(std::ostream &os) : os_(os), lvl_(0), new_line_(true) {}

	virtual void visit_decs(decs &s) override
	{
		for (auto *f : s.fundecs_)
			f->accept(*this);

		for (auto *v : s.vardecs_) {
			v->accept(*this);
			os_ << '\n';
		}
	}

	virtual void visit_vardec(vardec &s) override
	{
		indent() << s << " = ";

		s.rhs_->accept(*this);

		os_ << ';';
	}

	virtual void visit_argdec(argdec &s) override { os_ << s; }

	virtual void visit_fundec(fundec &s) override
	{
		os_ << "fun " << s.name_ << '(';

		for (auto it = s.args_.begin(); it != s.args_.end(); it++) {
			os_ << **it;
			if (it != s.args_.end() - 1)
				os_ << ", ";
		}

		os_ << ") " << s.ret_ty_.to_string() << " {\n";

		lvl_++;
		for (auto *b : s.body_) {
			new_line_ = true;
			b->accept(*this);
			os_ << '\n';
		}
		lvl_--;

		os_ << "}\n";
	}

	virtual void visit_sexp(sexp &s) override
	{
		indent();
		s.e_->accept(*this);
		os_ << ';';
	}

	virtual void visit_ret(ret &s) override
	{
		indent() << "return";
		if (s.e_) {
			os_ << ' ';
			s.e_->accept(*this);
		}
		os_ << ";";
	}

	virtual void visit_ifstmt(ifstmt &s) override
	{
		indent() << "if (";
		s.cond_->accept(*this);
		os_ << ")\n";

		lvl_++;
		for (auto *b : s.ibody_) {
			new_line_ = true;
			b->accept(*this);
			os_ << '\n';
		}
		lvl_--;

		if (s.ebody_.size() > 0) {
			new_line_ = true;
			indent() << "else\n";
			lvl_++;
			for (auto *b : s.ebody_) {
				new_line_ = true;
				b->accept(*this);
				os_ << '\n';
			}
			lvl_--;
		}

		new_line_ = true;
		indent() << "fi";
	}

	virtual void visit_forstmt(forstmt &s) override
	{
		indent() << "for (";
		s.init_->accept(*this);
		os_ << " ";
		s.cond_->accept(*this);
		os_ << "; ";
		s.action_->accept(*this);
		os_ << ")\n";

		lvl_++;
		for (auto *b : s.body_) {
			new_line_ = true;
			b->accept(*this);
			os_ << '\n';
		}

		lvl_--;
		new_line_ = true;
		indent() << "rof";
	}

	virtual void visit_ass(ass &s) override
	{
		indent();
		s.lhs_->accept(*this);
		os_ << " = ";
		s.rhs_->accept(*this);
	}

	/* expressions */
	virtual void visit_bin(bin &e) override
	{
		e.lhs_->accept(*this);
		os_ << " " << binop_to_string(e.op_) << " ";
		e.rhs_->accept(*this);
	}

	virtual void visit_cmp(cmp &e) override
	{
		e.lhs_->accept(*this);
		os_ << " " << cmpop_to_string(e.op_) << " ";
		e.rhs_->accept(*this);
	}

	virtual void visit_num(num &e) override { os_ << e.value_; }

	virtual void visit_ref(ref &e) override
	{
		if (e.dec_) {
			os_ << e.dec_->name_;
			if (e.dec_->escapes_)
				os_ << "^";
		} else
			os_ << e.name_;
	}

	virtual void visit_deref(deref &e) override
	{
		os_ << '*';
		e.e_->accept(*this);
	}

	virtual void visit_addrof(addrof &e) override
	{
		os_ << '&';
		e.e_->accept(*this);
	}

	virtual void visit_call(call &e) override
	{
		if (e.fdec_)
			os_ << e.fdec_->name_;
		else
			os_ << e.name_;
		os_ << '(';

		for (auto it = e.args_.begin(); it != e.args_.end(); it++) {
			(*it)->accept(*this);
			if (it != e.args_.end() - 1)
				os_ << ", ";
		}

		os_ << ')';
	}

	virtual void visit_str_lit(str_lit &e) override
	{
		os_ << '"' << e.str_ << '"';
	}

      private:
	std::ostream &indent()
	{
		if (new_line_) {
			for (unsigned i = 0; i < lvl_; i++)
				os_ << "    ";
			new_line_ = false;
		}
		return os_;
	}

	std::ostream &os_;
	unsigned lvl_;
	bool new_line_;
};
} // namespace frontend
