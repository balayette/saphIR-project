#include "frontend/sema/tycheck.hh"
#include "utils/assert.hh"

namespace frontend::sema
{
#define CHECK_TYPE_ERROR(L, R, S)                                              \
	do {                                                                   \
		if (!(L)->assign_compat(R)) {                                  \
			std::cerr << "TypeError: Incompatible types "          \
				  << (L)->to_string() << " and "               \
				  << (R)->to_string() << " in " << S << '\n';  \
			COMPILATION_ERROR(utils::cfail::SEMA);                 \
		}                                                              \
	} while (0)

tycheck_visitor::tycheck_visitor()
{
	tmap_.add("int", new types::builtin_ty(types::type::INT,
					       types::signedness::SIGNED));
	tmap_.add("uint", new types::builtin_ty(types::type::INT,
						types::signedness::UNSIGNED));
	tmap_.add("string", new types::builtin_ty(types::type::STRING,
						  types::signedness::INVALID));
	tmap_.add("void", new types::builtin_ty(types::type::VOID,
						types::signedness::INVALID));
}

// get_type must be used everytime there can be a refernce to a type.
// This includes function return values, function arguments declarations,
// local and global variables declarations, struct members declarations...
utils::ref<types::ty> tycheck_visitor::get_type(utils::ref<types::ty> t)
{
	return types::concretize_type(t, tmap_);
}

void tycheck_visitor::visit_paren(paren &e)
{
	default_visitor::visit_paren(e);

	e.ty_ = e.e_->ty_;
}

void tycheck_visitor::visit_cast(cast &e)
{
	default_visitor::visit_cast(e);

	auto ty = get_type(e.ty_);
	if (!e.e_->ty_->cast_compat(&ty)) {
		std::cerr << "TypeError: '" << e.e_->ty_->to_string()
			  << "' can't be cast to '" << ty->to_string() << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
	e.ty_ = ty;
}

void tycheck_visitor::visit_globaldec(globaldec &s)
{
	default_visitor::visit_globaldec(s);

	s.type_ = get_type(s.type_);

	CHECK_TYPE_ERROR(&s.type_, &s.rhs_->ty_,
			 "declaration of variable '" << s.name_ << "'");
}

void tycheck_visitor::visit_structdec(structdec &s)
{
	default_visitor::visit_structdec(s);

	std::vector<utils::ref<types::ty>> types;
	std::vector<symbol> names;
	for (auto mem : s.members_) {
		types.push_back(mem->type_);
		names.push_back(mem->name_);
	}

	s.type_ = new types::struct_ty(s.name_, names, types);
	tmap_.add(s.name_, s.type_);
}

void tycheck_visitor::visit_memberdec(memberdec &s)
{
	s.type_ = get_type(s.type_);
}

void tycheck_visitor::visit_locdec(locdec &s)
{
	default_visitor::visit_locdec(s);

	s.type_ = get_type(s.type_);

	if (s.rhs_)
		CHECK_TYPE_ERROR(&s.type_, &s.rhs_->ty_,
				 "declaration of variable '" << s.name_ << "'");
}

void tycheck_visitor::visit_funprotodec(funprotodec &s)
{
	std::vector<utils::ref<types::ty>> arg_tys;
	for (auto arg : s.args_) {
		arg->type_ = get_type(arg->type_);
		arg_tys.push_back(arg->type_);
	}
	auto ret_ty = get_type(s.type_);
	s.type_ = new types::fun_ty(ret_ty, arg_tys, s.variadic_);
}

void tycheck_visitor::visit_fundec(fundec &s)
{
	std::vector<utils::ref<types::ty>> arg_tys;
	for (auto arg : s.args_) {
		arg->type_ = get_type(arg->type_);
		arg_tys.push_back(arg->type_);
	}

	auto ret_ty = get_type(s.type_);
	if (ret_ty.as<types::composite_ty>()) {
		std::cerr << "TypeError: Cannot return composite type '"
			  << ret_ty->to_string() << "' in function '" << s.name_
			  << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	s.type_ = new types::fun_ty(ret_ty, arg_tys, s.variadic_);

	if (!s.has_return_)
		CHECK_TYPE_ERROR(&types::void_type(), &s.type_,
				 "function '" << s.name_
					      << "' without return statement");

	default_visitor::visit_fundec(s);
}

void tycheck_visitor::visit_ref(ref &e)
{
	default_visitor::visit_ref(e);
	e.ty_ = e.dec_->type_;
}

void tycheck_visitor::visit_ret(ret &s)
{
	default_visitor::visit_ret(s);

	auto fty = s.fdec_->type_.as<types::fun_ty>();

	/* return; in void function */
	if (s.e_ == nullptr)
		CHECK_TYPE_ERROR(&types::void_type(), &fty->ret_ty_,
				 "function '" << s.fdec_->name_
					      << "' return statement");
	else
		CHECK_TYPE_ERROR(&fty->ret_ty_, &s.e_->ty_,
				 "function '" << s.fdec_->name_
					      << "' return statement");
}

void tycheck_visitor::visit_ifstmt(ifstmt &s)
{
	default_visitor::visit_ifstmt(s);

	CHECK_TYPE_ERROR(&s.cond_->ty_, &types::integer_type(), "if condition");
}


void tycheck_visitor::visit_forstmt(forstmt &s)
{
	default_visitor::visit_forstmt(s);

	CHECK_TYPE_ERROR(&s.cond_->ty_, &types::integer_type(),
			 "for condition");
}

void tycheck_visitor::visit_ass(ass &s)
{
	default_visitor::visit_ass(s);

	CHECK_TYPE_ERROR(&s.lhs_->ty_, &s.rhs_->ty_, "assignment");
}

void tycheck_visitor::visit_bin(bin &e)
{
	default_visitor::visit_bin(e);

	// XXX: binop_compat
	auto ty = e.lhs_->ty_->binop_compat(e.op_, &e.rhs_->ty_);
	if (!ty) {
		std::cerr << "TypeError: Incompatible types '"
			  << e.lhs_->ty_->to_string() << "' and '"
			  << e.rhs_->ty_->to_string() << "' in "
			  << ops::binop_to_string(e.op_) << '\n';
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	e.ty_ = ty;
}

void tycheck_visitor::visit_unary(unary &e)
{
	default_visitor::visit_unary(e);

	auto ty = e.e_->ty_->unaryop_type(e.op_);
	if (!ty) {
		std::cerr << "TypeError: Incompatible type '"
			  << e.e_->ty_->to_string() << "' and unary operator '"
			  << ops::unaryop_to_string(e.op_) << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	e.ty_ = ty;
}

void tycheck_visitor::visit_braceinit(braceinit &e)
{
	default_visitor::visit_braceinit(e);

	std::vector<utils::ref<types::ty>> types;
	for (auto e : e.exps_)
		types.push_back(e->ty_);

	e.ty_ = new types::braceinit_ty(types);
}

void tycheck_visitor::visit_cmp(cmp &e)
{
	default_visitor::visit_cmp(e);

	CHECK_TYPE_ERROR(&e.lhs_->ty_, &e.rhs_->ty_,
			 ops::cmpop_to_string(e.op_));
}

void tycheck_visitor::visit_deref(deref &e)
{
	default_visitor::visit_deref(e);

	if (!e.e_->ty_.as<types::pointer_ty>()) {
		std::cerr << "TypeError: Can't derefence "
			  << e.e_->ty_->to_string() << ": not pointer type.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	e.ty_ = types::deref_pointer_type(e.e_->ty_);
}

void tycheck_visitor::visit_addrof(addrof &e)
{
	default_visitor::visit_addrof(e);

	e.ty_ = new types::pointer_ty(e.e_->ty_);

	if (e.ty_->assign_compat(&types::void_type())) {
		std::cerr << "TypeError: Pointers to void are not supported.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_call(call &e)
{
	default_visitor::visit_call(e);

	auto fty = get_type(types::normalize_function_pointer(e.f_->ty_))
			   .as<types::fun_ty>();
	ASSERT(fty, "Not a function pointer");

	e.fty_ = fty;
	e.ty_ = fty->ret_ty_;

	for (size_t i = 0; i < fty->arg_tys_.size(); i++) {
		CHECK_TYPE_ERROR(fty->arg_tys_[i], &e.args_[i]->ty_,
				 "argument of function call");
	}
}

void tycheck_visitor::visit_memberaccess(memberaccess &e)
{
	default_visitor::visit_memberaccess(e);

	if (e.e_->ty_.as<types::pointer_ty>()) {
		std::cerr << "TypeError: Operator '.' on pointer type '"
			  << e.e_->ty_->to_string() << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	auto st = e.e_->ty_.as<types::struct_ty>();
	if (!st) {
		std::cerr << "Accessing member '" << e.member_
			  << "' on non struct.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	auto idx = st->member_index(e.member_);
	if (idx == std::nullopt) {
		std::cerr << "Member '" << e.member_ << "' of type '"
			  << st->to_string() << "' doesn't exist.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	e.ty_ = st->types_[*idx];
}

void tycheck_visitor::visit_arrowaccess(arrowaccess &e)
{
	default_visitor::visit_arrowaccess(e);

	auto pt = e.e_->ty_.as<types::pointer_ty>();
	if (!pt) {
		std::cerr << "TypeError: Arrow accessing member '" << e.member_
			  << "' on non pointer type '" << e.e_->ty_->to_string()
			  << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
	if (pt->ptr_ != 1) {
		std::cerr << "TypeError: Arrow accessing member '" << e.member_
			  << "' on non pointer to struct type '"
			  << e.e_->ty_->to_string() << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	auto st = pt->ty_.as<types::struct_ty>();
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

void tycheck_visitor::visit_subscript(subscript &e)
{
	default_visitor::visit_subscript(e);

	CHECK_TYPE_ERROR(&e.index_->ty_, &types::integer_type(),
			 "array subscript");
	if (!e.base_->ty_.as<types::pointer_ty>()
	    && !e.base_->ty_.as<types::array_ty>()) {
		std::cerr
			<< "TypeError: Subscript operator on non pointer of type '"
			<< e.base_->ty_->to_string() << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
	e.ty_ = types::deref_pointer_type(e.base_->ty_);
}

} // namespace frontend::sema
