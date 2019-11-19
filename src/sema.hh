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

		if (!s.rhs_->ty_.compatible(s.type_)) {
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

		if (!s.has_return_ && s.ret_ty_ != types::type::VOID) {
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

		if (!s.cond_->ty_.compatible(types::type::INT)) {
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

		if (!s.cond_->ty_.compatible(types::type::INT)) {
			std::cerr << "TypeError: Wrong type for cond in for\n";
			std::exit(2);
		}
	}

	virtual void visit_ass(ass &s) override
	{
		default_visitor::visit_ass(s);

		if (!s.lhs_->ty_.compatible(s.rhs_->ty_)) {
			std::cerr << "TypeError: Wrong type for rhs of ass.\n";
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
		e.dec_ = *v;

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
		e.fdec_ = *f;

		default_visitor::visit_call(e);

		for (size_t i = 0; i < e.args_.size(); i++) {
			if (e.args_[i]->ty_.compatible((*f)->args_[i]->type_))
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

		if (!e.lhs_->ty_.compatible(e.rhs_->ty_)) {
			std::cerr << "TypeError: Incompatible types in cmp\n";
			std::exit(2);
		}
	}

	virtual void visit_bin(bin &e) override
	{
		default_visitor::visit_bin(e);

		if (!e.lhs_->ty_.compatible(e.rhs_->ty_)) {
			std::cerr << "TypeError: Incompatible types in bin\n";
			std::exit(2);
		}

		/* TODO: This only works in the basic case */
		e.ty_ = e.lhs_->ty_;
	}

	virtual void visit_ret(ret &s) override
	{
		default_visitor::visit_ret(s);

		cfunc_->has_return_ = true;
		s.fdec_ = cfunc_.get();

		/* return; in void function */
		if (s.e_ == nullptr && cfunc_->ret_ty_ == types::type::VOID)
			return;

		if (s.e_ == nullptr /* return; in non void function */
		    || !s.e_->ty_.compatible(cfunc_->ret_ty_)) {
			std::cerr
				<< "TypeError: Incompatible return type in fun "
				<< cfunc_->name_ << '\n';
			std::exit(2);
		}
	}

	virtual void visit_addrof(addrof &e) override
	{
		default_visitor::visit_addrof(e);

		if (e.ty_ == types::type::VOID) {
			std::cerr << "Pointer to void are not supported.\n";
			std::exit(2);
		}

		e.ty_ = e.e_->ty_;
		e.ty_.ptr_++;
	}

	virtual void visit_deref(deref &e) override
	{
		default_visitor::visit_deref(e);

		if (!e.e_->ty_.ptr_) {
			std::cerr << "Can't derefence non pointer type.\n";
			std::exit(2);
		}

		e.ty_ = e.e_->ty_;
		e.ty_.ptr_--;
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
