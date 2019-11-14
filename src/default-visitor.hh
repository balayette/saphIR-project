#include "visitor.hh"

class default_visitor : public visitor
{
      public:
	void visit_bin(bin &e) override
	{
		e.lhs_->accept(*this);
		e.rhs_->accept(*this);
	}

	void visit_num(num &) override {}

	void visit_seq(seq &e) override
	{
		for (auto *child : e.children_)
			child->accept(*this);
	}

	void visit_id(id &) override {}
};
