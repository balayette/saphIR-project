#include "frontend/sema/sema.hh"

namespace frontend::sema
{
void binding_visitor::visit_decs(decs &s)
{
	for (auto *v : s.vardecs_)
		v->accept(*this);
	for (auto *f : s.fundecs_) {
		f->accept(*this);
		if (!fmap_.add(f->name_, f)) {
			std::cerr << "fun '" << f->name_
				  << "' already declared\n";
			std::exit(2);
		}
	}
}

void binding_visitor::visit_vardec(vardec &s)
{
	default_visitor::visit_vardec(s);
	if (!vmap_.add(s.name_, &s)) {
		std::cerr << "var '" << s.name_ << "' already declared.\n";
		std::exit(2);
	}

	if (!s.rhs_->ty_.compatible(s.type_)) {
		std::cerr << "TypeError: rhs of declaration of variable '"
			  << s.name_ << "'\n";
		std::exit(2);
	}
}

void binding_visitor::visit_argdec(argdec &s)
{
	default_visitor::visit_argdec(s);
	if (!vmap_.add(s.name_, &s)) {
		std::cerr << "arg '" << s.name_ << "' already declared.\n";
		std::exit(2);
	}
}

void binding_visitor::visit_fundec(fundec &s)
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

void binding_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);

	if (!s.cond_->ty_.compatible(types::type::INT)) {
		std::cerr << "TypeError: Wrong type for comparison in if\n";
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

void binding_visitor::visit_forstmt(forstmt &s)
{
	new_scope();
	default_visitor::visit_forstmt(s);
	end_scope();

	if (!s.cond_->ty_.compatible(types::type::INT)) {
		std::cerr << "TypeError: Wrong type for cond in for\n";
		std::exit(2);
	}
}

void binding_visitor::visit_ass(ass &s)
{
	default_visitor::visit_ass(s);

	if (!s.lhs_->ty_.compatible(s.rhs_->ty_)) {
		std::cerr << "TypeError: Wrong type for rhs of ass.\n";
		std::exit(2);
	}
}

void binding_visitor::visit_ref(ref &e)
{
	auto v = vmap_.get(e.name_);

	if (v == std::nullopt) {
		std::cerr << "ref: var " << e.name_
			  << " used before definition.\n";
		std::exit(2);
	}
	std::cout << "ref: " << e.name_ << " bound to variable " << *v << '\n';
	e.ty_ = (*v)->type_;
	e.dec_ = *v;

	default_visitor::visit_ref(e);
}

void binding_visitor::visit_call(call &e)
{
	auto f = fmap_.get(e.name_);

	if (f == std::nullopt) {
		std::cerr << "call: Couldn't find a definition for fun '"
			  << e.name_ << "'\n";
		std::exit(2);
	}
	std::cout << "call: " << e.name_ << " bound to function " << *f << '\n';

	if (e.args_.size() != (*f)->args_.size()) {
		std::cerr << "call: Wrong number of arguments for fun '"
			  << e.name_ << "', expected " << (*f)->args_.size()
			  << ", got " << e.args_.size() << '\n';
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

void binding_visitor::visit_cmp(cmp &e)
{
	default_visitor::visit_cmp(e);

	if (!e.lhs_->ty_.compatible(e.rhs_->ty_)) {
		std::cerr << "TypeError: Incompatible types in cmp\n";
		std::exit(2);
	}
}

void binding_visitor::visit_bin(bin &e)
{
	default_visitor::visit_bin(e);

	if (!e.lhs_->ty_.compatible(e.rhs_->ty_)) {
		std::cerr << "TypeError: Incompatible types in bin\n";
		std::exit(2);
	}

	/* TODO: This only works in the basic case */
	e.ty_ = e.lhs_->ty_;
}

void binding_visitor::visit_ret(ret &s)
{
	default_visitor::visit_ret(s);

	cfunc_->has_return_ = true;
	s.fdec_ = cfunc_.get();

	/* return; in void function */
	if (s.e_ == nullptr && cfunc_->ret_ty_ == types::type::VOID)
		return;

	if (s.e_ == nullptr /* return; in non void function */
	    || !s.e_->ty_.compatible(cfunc_->ret_ty_)) {
		std::cerr << "TypeError: Incompatible return type in fun "
			  << cfunc_->name_ << '\n';
		std::exit(2);
	}
}

void binding_visitor::visit_addrof(addrof &e)
{
	default_visitor::visit_addrof(e);

	if (e.ty_ == types::type::VOID) {
		std::cerr << "Pointer to void are not supported.\n";
		std::exit(2);
	}

	e.ty_ = e.e_->ty_;
	e.ty_.ptr_++;
}

void binding_visitor::visit_deref(deref &e)
{
	default_visitor::visit_deref(e);

	if (!e.e_->ty_.ptr_) {
		std::cerr << "Can't derefence non pointer type.\n";
		std::exit(2);
	}

	e.ty_ = e.e_->ty_;
	e.ty_.ptr_--;
}

void binding_visitor::new_scope()
{
	fmap_.new_scope();
	vmap_.new_scope();
}

void binding_visitor::end_scope()
{
	fmap_.end_scope();
	vmap_.end_scope();
}

void escapes_visitor::visit_addrof(addrof &e)
{
	default_visitor::visit_addrof(e);

	if (auto *d = dynamic_cast<ref *>(e.e_)) {
		if (!d->dec_->escapes_)
			std::cout << "escape: var '" << d->dec_->name_
				  << "' escapes\n";
		d->dec_->escapes_ = true;
	}
}

void frame_visitor::visit_fundec(fundec &s)
{
	std::vector<bool> escaping;
	for (auto *arg : s.args_)
		escaping.push_back(arg->escapes_);

	cframe_ = new mach::frame(unique_label(s.name_.get()), escaping);
	for (unsigned i = 0; i < s.args_.size(); i++)
		s.args_[i]->access_ = cframe_->formals_[i];

	s.frame_ = cframe_;
	std::cout << "frame: fun '" << s.name_ << "' at label " << cframe_->s_
		  << '\n';
	for (size_t i = 0; i < s.args_.size(); i++) {
		std::cout << "frame: arg '" << s.args_[i]->name_ << "' "
			  << cframe_->formals_[i] << '\n';
	}
	default_visitor::visit_fundec(s);
	cframe_ = nullptr;
}

void frame_visitor::visit_vardec(vardec &s)
{
	s.access_ = cframe_->alloc_local(s.escapes_);
	std::cout << "frame: var '" << s.name_ << "' " << s.access_ << '\n';
	default_visitor::visit_vardec(s);
}
} // namespace frontend::sema
