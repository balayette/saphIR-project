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

	void visit_num(num &n) override { s_ << n.value_; }

	void visit_id(id &i) override { s_ << i.id_; }

      private:
	std::ostream &s_;
};
