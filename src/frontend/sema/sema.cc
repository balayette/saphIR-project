#include "frontend/sema/sema.hh"
#include "utils/assert.hh"

namespace frontend::sema
{
void binding_visitor::visit_decs(decs &s)
{
	for (auto *d : s.decs_) {
		d->accept(*this);
	}
}

void binding_visitor::visit_funprotodec(funprotodec &s)
{
	if (!fmap_.add(s.name_, &s)) {
		std::cerr << "fun '" << s.name_ << "' already declared\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	std::vector<utils::ref<types::ty>> arg_tys;
	for (auto *arg : s.args_) {
		arg->type_ = get_type(arg->type_);
		arg_tys.push_back(arg->type_);
	}
	auto ret_ty = get_type(s.type_);
	s.type_ = new types::fun_ty(ret_ty, arg_tys, s.variadic_);
}

void binding_visitor::visit_memberdec(memberdec &s)
{
	s.type_ = get_type(s.type_);
}

void binding_visitor::visit_structdec(structdec &s)
{
	default_visitor::visit_structdec(s);

	std::vector<utils::ref<types::ty>> types;
	std::vector<symbol> names;
	for (auto *mem : s.members_) {
		types.push_back(mem->type_);
		names.push_back(mem->name_);
	}

	s.type_ = new types::struct_ty(s.name_, names, types);
	tmap_.add(s.name_, s.type_);
}

void binding_visitor::visit_globaldec(globaldec &s)
{
	default_visitor::visit_globaldec(s);
	if (!vmap_.add(s.name_, &s)) {
		std::cerr << "var '" << s.name_ << "' already declared.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	s.type_ = get_type(s.type_);
}

void binding_visitor::visit_paren(paren &e)
{
	default_visitor::visit_paren(e);

	e.ty_ = e.e_->ty_;
}

void binding_visitor::visit_locdec(locdec &s)
{
	default_visitor::visit_locdec(s);
	if (!vmap_.add(s.name_, &s)) {
		std::cerr << "var '" << s.name_ << "' already declared.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	s.type_ = get_type(s.type_);
}

void binding_visitor::visit_fundec(fundec &s)
{
	if (!fmap_.add(s.name_, &s)) {
		std::cerr << "fun '" << s.name_ << "' already declared\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	std::vector<utils::ref<types::ty>> arg_tys;
	for (auto *arg : s.args_) {
		arg->type_ = get_type(arg->type_);
		arg_tys.push_back(arg->type_);
	}
	auto ret_ty = get_type(s.type_);
	s.type_ = new types::fun_ty(ret_ty, arg_tys, s.variadic_);

	new_scope();
	cfunc_.enter(&s);

	for (auto *arg : s.args_)
		arg->accept(*this);
	for (auto *b : s.body_)
		b->accept(*this);

	cfunc_.leave();
	end_scope();
}

void binding_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);

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
}

void binding_visitor::visit_ref(ref &e)
{
	auto v = vmap_.get(e.name_);

	if (v == std::nullopt) {
		std::cerr << "ref: var " << e.name_
			  << " used before definition.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
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
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
	std::cout << "call: " << e.name_ << " bound to function " << *f << '\n';

	if (!(*f)->variadic_) {
		if (e.args_.size() != (*f)->args_.size()) {
			std::cerr << "call: Wrong number of arguments for fun '"
				  << e.name_ << "', expected "
				  << (*f)->args_.size() << ", got "
				  << e.args_.size() << '\n';
			COMPILATION_ERROR(utils::cfail::SEMA);
		}
	} else {
		if (e.args_.size() < (*f)->args_.size()) {
			std::cerr
				<< "call: Wrong number of arguments for variadic fun '"
				<< e.name_
				<< "', expected >=" << (*f)->args_.size()
				<< ", got " << e.args_.size() << '\n';
			COMPILATION_ERROR(utils::cfail::SEMA);
		}
	}

	e.ty_ = (*f)->type_;
	e.fdec_ = *f;

	default_visitor::visit_call(e);
}

void binding_visitor::visit_bin(bin &e)
{
	default_visitor::visit_bin(e);

	/* TODO: This only works in the basic case, move it to tycheck? */
	e.ty_ = e.lhs_->ty_;
}

void binding_visitor::visit_ret(ret &s)
{
	default_visitor::visit_ret(s);

	cfunc_->has_return_ = true;
	s.fdec_ = cfunc_.get();
}

void binding_visitor::visit_braceinit(braceinit &e)
{
	default_visitor::visit_braceinit(e);

	std::vector<utils::ref<types::ty>> types;
	for (auto *e : e.exps_)
		types.push_back(e->ty_);

	e.ty_ = new types::braceinit_ty(types);
}

void binding_visitor::visit_addrof(addrof &e)
{
	default_visitor::visit_addrof(e);

	e.ty_ = e.e_->ty_->clone();
	e.ty_->ptr_++;
}

void binding_visitor::visit_deref(deref &e)
{
	default_visitor::visit_deref(e);

	e.ty_ = e.e_->ty_->clone();
	e.ty_->ptr_--;
}

void binding_visitor::visit_memberaccess(memberaccess &e)
{
	default_visitor::visit_memberaccess(e);

	auto st = e.e_->ty_.as<types::struct_ty>();
	if (!st) {
		std::cerr << "Accessing member '" << e.member_
			  << "' on non struct.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	auto idx = st->member_index(e.member_);
	if (idx == std::nullopt) {
		std::cerr << "Member '" << e.member_ << "' doesn't exist.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	e.ty_ = st->types_[*idx];
}

void binding_visitor::visit_arrowaccess(arrowaccess &e)
{
	default_visitor::visit_arrowaccess(e);

	auto st = e.e_->ty_.as<types::struct_ty>();
	if (!st) {
		std::cerr << "Arrow accessing member '" << e.member_
			  << "' on non struct.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	auto idx = st->member_index(e.member_);
	if (idx == std::nullopt) {
		std::cerr << "Member '" << e.member_ << "' doesn't exist.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	e.ty_ = st->types_[*idx];
}

// get_type must be used everytime there can be a refernce to a type.
// This includes function return values, function arguments declarations,
// local and global variables declarations, struct members declarations...
utils::ref<types::ty> binding_visitor::get_type(utils::ref<types::ty> t)
{
	utils::ref<types::named_ty> nt = t.as<types::named_ty>();
	if (!nt)
		return t;

	auto type = tmap_.get(nt->name_);
	if (type == std::nullopt) {
		std::cerr << "Type '" << nt->name_ << "' doesn't exist.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	utils::ref<types::ty> ret = (*type)->clone();

	ret->ptr_ = nt->ptr_;
	return ret;
}

void binding_visitor::new_scope()
{
	fmap_.new_scope();
	vmap_.new_scope();
	tmap_.new_scope();
}

void binding_visitor::end_scope()
{
	fmap_.end_scope();
	vmap_.end_scope();
	tmap_.end_scope();
}

binding_visitor::binding_visitor()
{
	;
	tmap_.add("int", new types::builtin_ty(types::type::INT, 8, 0));
	tmap_.add("string", new types::builtin_ty(types::type::STRING, 8, 0));
	tmap_.add("void", new types::builtin_ty(types::type::VOID, 0, 0));
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

void escapes_visitor::visit_locdec(locdec &e)
{
	default_visitor::visit_locdec(e);

	// All structs are stored on the stack
	// XXX: Allow structs in registers (hard?)
	if (auto si = e.type_.as<types::struct_ty>())
		e.escapes_ = si->ptr_ == 0;
}

void frame_visitor::visit_funprotodec(funprotodec &)
{
	// Don't recurse.
}

void frame_visitor::visit_fundec(fundec &s)
{
	std::vector<bool> escaping;
	std::vector<utils::ref<types::ty>> types;
	for (auto *arg : s.args_) {
		escaping.push_back(arg->escapes_);
		types.push_back(arg->type_);
	}

	cframe_ = new mach::frame(s.name_, escaping, types);
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

void frame_visitor::visit_globaldec(globaldec &s)
{
	s.access_ = new mach::global_acc(s.name_, s.type_);
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
