#pragma once

#include "stmt.hh"
#include "exp.hh"
#include "default-visitor.hh"
#include "symbol.hh"
#include "scoped.hh"

#include <unordered_map>
#include <iostream>
#include <stack>

namespace sema
{

class binding_visitor : public default_visitor
{
      public:
	/* Top level node, so don't push a new scope */
	virtual void visit_decs(decs &s) override
	{
		for (auto *v : s.vardecs_)
			v->accept(*this);
		for (auto *f : s.fundecs_) {
			f->accept(*this);
			fmap_.add(f->name_, f);
		}
	};

	virtual void visit_vardec(vardec &s) override
	{
		default_visitor::visit_vardec(s);
		vmap_.add(s.name_, &s);

		if (!are_compatible(s.rhs_->ty_, s.type_)) {
			std::cerr
				<< "TypeError: rhs of declaration of variable '"
				<< s.name_ << "'\n";
			std::exit(2);
		}
	}

	virtual void visit_argdec(argdec &s) override
	{
		default_visitor::visit_argdec(s);
		vmap_.add(s.name_, &s);
	}

	virtual void visit_fundec(fundec &s) override
	{
		new_scope();
		cfunc_.enter(&s);

		for (auto *arg : s.args_)
			arg->accept(*this);
		for (auto *b : s.body_)
			b->accept(*this);

		if (!s.has_return_ && s.ret_ty_ != types::ty::VOID) {
			std::cerr << "TypeError: Missing return stmt in fun '"
				  << s.name_ << "' with return type != void\n";
			std::exit(2);
		}

		cfunc_.leave();
		end_scope();
	}

	virtual void visit_ifstmt(ifstmt &s) override
	{
		s.cond_->accept(*this);

		if (!are_compatible(s.cond_->ty_, types::ty::INT)) {
			std::cerr
				<< "TypeError: Wrong type for comparison in if\n";
			std::exit(2);
		}

		new_scope();
		for (auto *i : s.ibody_)
			i->accept(*this);
		end_scope();
		new_scope();
		for (auto *e : s.ebody_)
			e->accept(*this);
		end_scope();
	}

	virtual void visit_forstmt(forstmt &s) override
	{
		new_scope();
		default_visitor::visit_forstmt(s);
		end_scope();

		if (!are_compatible(s.cond_->ty_, types::ty::INT)) {
			std::cerr << "TypeError: Wrong type for cond in for\n";
			std::exit(2);
		}
	}

	virtual void visit_ass(ass &e) override
	{
		auto v = vmap_.get(e.id_);
		if (v == std::nullopt) {
			std::cerr << "ass: var " << e.id_
				  << " assigned before definition.\n";
			std::exit(2);
		}
		std::cout << "ass: " << e.id_ << " bound to variable " << *v
			  << '\n';

		default_visitor::visit_ass(e);

		if (!are_compatible((*v)->type_, e.rhs_->ty_)) {
			std::cerr
				<< "TypeError: rhs of assignment of variable '"
				<< e.id_ << "'\n";
			std::exit(2);
		}
	}

	virtual void visit_ref(ref &e) override
	{
		auto v = vmap_.get(e.name_);

		if (v == std::nullopt) {
			std::cerr << "ref: var " << e.name_
				  << " used before definition.\n";
			std::exit(2);
		}
		std::cout << "ref: " << e.name_ << " bound to variable " << *v
			  << '\n';
		e.ty_ = (*v)->type_;

		default_visitor::visit_ref(e);
	}

	virtual void visit_call(call &e) override
	{
		auto f = fmap_.get(e.name_);

		if (f == std::nullopt) {
			std::cerr
				<< "call: Couldn't find a definition for fun '"
				<< e.name_ << "'\n";
			std::exit(2);
		}
		std::cout << "call: " << e.name_ << " bound to function " << *f
			  << '\n';

		if (e.args_.size() != (*f)->args_.size()) {
			std::cerr << "call: Wrong number of arguments for fun '"
				  << e.name_ << "', expected "
				  << (*f)->args_.size() << ", got "
				  << e.args_.size() << '\n';
			std::exit(2);
		}

		e.ty_ = (*f)->ret_ty_;

		default_visitor::visit_call(e);

		for (size_t i = 0; i < e.args_.size(); i++) {
			if (are_compatible(e.args_[i]->ty_,
					   (*f)->args_[i]->type_))
				continue;
			std::cerr << "TypeError: Wrong type for argument '"
				  << (*f)->args_[i]->name_ << "' of call to '"
				  << e.name_ << "'\n";
			std::exit(2);
		}
	}

	virtual void visit_cmp(cmp &e) override
	{
		default_visitor::visit_cmp(e);

		if (!are_compatible(e.lhs_->ty_, e.rhs_->ty_)) {
			std::cerr << "TypeError: Incompatible types in cmp\n";
			std::exit(2);
		}
	}

	virtual void visit_bin(bin &e) override
	{
		default_visitor::visit_bin(e);

		if (!are_compatible(e.lhs_->ty_, e.rhs_->ty_)) {
			std::cerr << "TypeError: Incompatible types in bin\n";
			std::exit(2);
		}
	}

	virtual void visit_ret(ret &s) override
	{
		default_visitor::visit_ret(s);

		cfunc_->has_return_ = true;

		/* return; in void function */
		if (s.e_ == nullptr && cfunc_->ret_ty_ == types::ty::VOID)
			return;

		if (s.e_ == nullptr /* return; in non void function */
		    || !are_compatible(s.e_->ty_, cfunc_->ret_ty_)) {
			std::cerr
				<< "TypeError: Incompatible return type in fun "
				<< cfunc_->name_ << '\n';
			std::exit(2);
		}
	}

      private:
	void new_scope()
	{
		fmap_.new_scope();
		vmap_.new_scope();
	}

	void end_scope()
	{
		fmap_.end_scope();
		vmap_.end_scope();
	}

	scoped_map<symbol, fundec *> fmap_;
	scoped_map<symbol, dec *> vmap_;
	scoped_ptr<fundec *> cfunc_;
};
} // namespace sema
