#include "frontend/sema/sema.hh"
#include "utils/assert.hh"

namespace frontend::sema
{
void binding_visitor::visit_funprotodec(funprotodec &s)
{
	if (!fmap_.add(s.name_, &s)) {
		std::cerr << "fun '" << s.name_ << "' already declared\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void binding_visitor::visit_globaldec(globaldec &s)
{
	default_visitor::visit_globaldec(s);
	if (!vmap_.add(s.name_, &s)) {
		std::cerr << "var '" << s.name_ << "' already declared.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void binding_visitor::visit_locdec(locdec &s)
{
	default_visitor::visit_locdec(s);
	if (!vmap_.add(s.name_, &s)) {
		std::cerr << "var '" << s.name_ << "' already declared.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void binding_visitor::visit_fundec(fundec &s)
{
	if (!fmap_.add(s.name_, &s)) {
		std::cerr << "fun '" << s.name_ << "' already declared\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	new_scope();
	cfunc_.enter(&s);

	for (auto arg : s.args_)
		arg->accept(*this);
	for (auto b : s.body_)
		b->accept(*this);

	cfunc_.leave();
	end_scope();
}

void binding_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);

	new_scope();
	for (auto i : s.ibody_)
		i->accept(*this);
	end_scope();
	new_scope();
	for (auto e : s.ebody_)
		e->accept(*this);
	end_scope();
}

void binding_visitor::visit_forstmt(forstmt &s)
{
	new_scope();
	default_visitor::visit_forstmt(s);
	end_scope();
}

void binding_visitor::visit_ref(ref &e)
{
	default_visitor::visit_ref(e);
	auto f = fmap_.get(e.name_);
	if (f != std::nullopt) {
		e.dec_ = *f;
		return;
	}

	auto v = vmap_.get(e.name_);

	if (v == std::nullopt) {
		std::cerr << "ref: var " << e.name_
			  << " used before definition.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
	e.dec_ = *v;
}

void binding_visitor::visit_ret(ret &s)
{
	default_visitor::visit_ret(s);

	cfunc_->has_return_ = true;
	s.fdec_ = cfunc_.get();
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

	if (auto d = e.e_.as<ref>()) {
		if (!d->dec_->escapes_)
			std::cout << "escape: var '" << d->dec_->name_
				  << "' escapes\n";
		d->dec_->escapes_ = true;
	}
}

void escapes_visitor::visit_locdec(locdec &e)
{
	default_visitor::visit_locdec(e);

	// All structs are stored on the stack
	// XXX: Allow structs in registers (hard?)
	e.escapes_ = e.type_.as<types::array_ty>() != nullptr
		     || e.type_.as<types::struct_ty>() != nullptr;
}

void frame_visitor::visit_funprotodec(funprotodec &s)
{
	// Don't recurse.
	s.access_ = target_.alloc_global(s.name_, s.type_);
}

void frame_visitor::visit_fundec(fundec &s)
{
	std::vector<bool> escaping;
	std::vector<utils::ref<types::ty>> types;
	for (auto arg : s.args_) {
		escaping.push_back(arg->escapes_);
		types.push_back(arg->type_);
	}

	cframe_ = target_.make_frame(s.name_, escaping, types, s.has_return_);
	auto formals = cframe_->formals();
	for (unsigned i = 0; i < s.args_.size(); i++)
		s.args_[i]->access_ = formals[i];

	s.frame_ = cframe_;
	std::cout << "frame: fun '" << s.name_ << "' at label " << cframe_->s_
		  << '\n';

	s.access_ = target_.alloc_global(s.name_, s.type_);
	default_visitor::visit_fundec(s);
	cframe_ = nullptr;
}

void frame_visitor::visit_globaldec(globaldec &s)
{
	s.access_ = target_.alloc_global(s.name_, s.type_);
	std::cout << "global var: '" << s.name_ << "' " << s.access_ << '\n';
	default_visitor::visit_globaldec(s);
}

void frame_visitor::visit_locdec(locdec &s)
{
	if (s.access_) // Already set by visit_fundec for args
		return;

	s.access_ = cframe_->alloc_local(s.escapes_, s.type_);
	std::cout << "frame: var '" << s.name_ << "' " << s.access_ << '\n';
	default_visitor::visit_locdec(s);
}

void frame_visitor::visit_call(call &) { cframe_->leaf_ = false; }
} // namespace frontend::sema
