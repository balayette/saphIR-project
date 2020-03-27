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

void tycheck_visitor::visit_globaldec(globaldec &s)
{
	default_visitor::visit_globaldec(s);

	CHECK_TYPE_ERROR(&s.type_, &s.rhs_->ty_,
			 "declaration of variable '" << s.name_ << "'");
}

void tycheck_visitor::visit_locdec(locdec &s)
{
	default_visitor::visit_locdec(s);

	if (s.rhs_)
		CHECK_TYPE_ERROR(&s.type_, &s.rhs_->ty_,
				 "declaration of variable '" << s.name_ << "'");
}

void tycheck_visitor::visit_fundec(fundec &s)
{
	default_visitor::visit_fundec(s);
	if (!s.has_return_)
		CHECK_TYPE_ERROR(&s.type_, &types::void_type(),
				 "function '" << s.name_
					      << "' without return statement");
}

void tycheck_visitor::visit_ret(ret &s)
{
	default_visitor::visit_ret(s);

	if (s.e_ == nullptr) {
		/* return; in void function */
		CHECK_TYPE_ERROR(&s.fdec_->type_, &types::void_type(),
				 "function '" << s.fdec_->name_
					      << "' return statement");
	}

	CHECK_TYPE_ERROR(&s.fdec_->type_, &s.e_->ty_,
			 "function '" << s.fdec_->name_
				      << "' return statement");
}

void tycheck_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);

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
	CHECK_TYPE_ERROR(&e.lhs_->ty_, &e.rhs_->ty_,
			 ops::binop_to_string(e.op_));
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

	if (!e.e_->ty_->ptr_) {
		std::cerr << "TypeError: Can't derefence "
			  << e.e_->ty_->to_string() << ": not pointer type.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_addrof(addrof &e)
{
	default_visitor::visit_addrof(e);

	if (e.ty_->assign_compat(&types::void_type())) {
		std::cerr << "TypeError: Pointers to void are not supported.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_call(call &e)
{
	default_visitor::visit_call(e);

	for (size_t i = 0; i < e.fdec_->args_.size(); i++) {
		CHECK_TYPE_ERROR(&e.args_[i]->ty_, &e.fdec_->args_[i]->type_,
				 "argument '" << e.fdec_->args_[i]->name_
					      << "' of call to function '"
					      << e.fdec_->name_ << "'");
	}
}

void tycheck_visitor::visit_memberaccess(memberaccess &e)
{
	default_visitor::visit_memberaccess(e);

	if (e.e_->ty_->ptr_) {
		std::cerr << "TypeError: Operator '.' on pointer type '"
			  << e.e_->ty_->to_string() << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_arrowaccess(arrowaccess &e)
{
	default_visitor::visit_arrowaccess(e);

	if (!e.e_->ty_->ptr_) {
		std::cerr << "TypeError: Arrow accessing member '" << e.member_
			  << "' on non pointer type '" << e.e_->ty_->to_string()
			  << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

} // namespace frontend::sema
