#include "visitor.hh"

class default_visitor : public visitor
{
      public:
	virtual void visit_bin(bin &e) override
	{
		e.lhs_->accept(*this);
		e.rhs_->accept(*this);
	}

	virtual void visit_num(num &) override {}

	virtual void visit_seq(seq &e) override
	{
		for (auto *child : e.children_)
			child->accept(*this);
	}

	virtual void visit_id(id &) override {}
};
