#include "ast.hh"
#include "default-visitor.hh"

namespace compiler
{

class remove_useless_seq : public default_visitor
{
	void visit_bin(bin &e)
	{
		bool recurse = false;
		if (auto *s = dynamic_cast<seq *>(e.lhs_)) {
			if (s->children_.size() == 1) {
				e.lhs_ = s->children_[0];
				s->children_.clear();
				delete s;
				recurse = true;
			}
		}
		if (auto *s = dynamic_cast<seq *>(e.rhs_)) {
			if (s->children_.size() == 1) {
				e.rhs_ = s->children_[0];
				s->children_.clear();
				delete s;
				recurse = true;
			}
		}

		if (recurse)
			e.accept(*this);
		e.lhs_->accept(*this);
		e.rhs_->accept(*this);
	}
};

exp *remove_seqs(exp *prog)
{
	remove_useless_seq r;
	/*
	while (auto *s = dynamic_cast<seq *>(prog)) {
		if (s->children_.size() == 1) {
			auto *tmp = s->children_[0];
			s->children_.clear();

			delete prog;
			prog = tmp;

			prog->accept(r);
		} else {
			for (size_t i = 0; i < s->children_.size(); i++)
				s->children_[i] = remove_seqs(s->children_[i]);
			break;
		}
	}
	*/
	prog->accept(r);

	return prog;
}

} // namespace compiler
