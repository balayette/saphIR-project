#pragma once
#include "default-visitor.hh"
#include <iostream>
#include <string>

class pretty_printer : public default_visitor
{
      public:
	pretty_printer(std::ostream &s) : s_(s) {}

	void visit_bin(bin &e) override
	{
		s_ << '(' << e.op_ << ' ';

		e.lhs_->accept(*this);
		s_ << ' ';
		e.rhs_->accept(*this);

		s_ << ')';
	}

	void visit_num(num &n) override { s_ << n.value_ << ' '; }

	void visit_id(id &i) override { s_ << i.id_ << ' '; }

	void visit_seq(seq &s) override
	{
		s_ << '[';
		default_visitor::visit_seq(s);
		s_ << ']';
	}

	void visit_fun(fun &f) override
	{
		s_ << "(FUN " << f.name_->id_ << " " << f.params_.size() << " (";
		for (auto *p : f.params_)
			s_ << p->id_ << ' ';
		s_ << ')';
		f.body_->accept(*this);
		s_ << ')';
	}

      private:
	std::ostream &s_;
};
