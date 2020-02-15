#include "frontend/sema/tycheck.hh"
#include "utils/assert.hh"

namespace frontend::sema
{
void tycheck_visitor::visit_globaldec(globaldec &s)
{
	default_visitor::visit_globaldec(s);

	if (!s.type_->compatible(&s.rhs_->ty_)) {
		std::cerr << "TypeError: rhs of declaration of variable '"
			  << s.name_ << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_locdec(locdec &s)
{
	default_visitor::visit_locdec(s);

	if (s.rhs_ && !s.rhs_->ty_->compatible(&s.type_)) {
		std::cerr << "TypeError: rhs of declaration of variable '"
			  << s.name_ << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_fundec(fundec &s)
{
	default_visitor::visit_fundec(s);
	if (!s.has_return_ && !s.type_->compatible(types::type::VOID)) {
		std::cerr << "TypeError: Missing return stmt in fun '"
			  << s.name_ << "' with return type != void\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_ret(ret &s)
{
	default_visitor::visit_ret(s);

	if (s.e_ == nullptr) {
		/* return; in void function */
		if (s.fdec_->type_->compatible(types::type::VOID))
			return;

		std::cerr << "TypeError: incompatible return type in fun "
			  << s.fdec_->name_ << '\n';
		COMPILATION_ERROR(utils::cfail::SEMA);
	}

	if (!s.fdec_->type_->compatible(&s.e_->ty_)) {
		std::cerr << "TypeError: return value in fun " << s.fdec_->name_
			  << '\n';
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_ifstmt(ifstmt &s)
{
	s.cond_->accept(*this);

	if (!s.cond_->ty_->compatible(types::type::INT)) {
		std::cerr << "TypeError: Wrong type for comparison in if\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}


void tycheck_visitor::visit_forstmt(forstmt &s)
{
	default_visitor::visit_forstmt(s);

	if (!s.cond_->ty_->compatible(types::type::INT)) {
		std::cerr << "TypeError: Wrong type for cond in for\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_ass(ass &s)
{
	default_visitor::visit_ass(s);

	if (!s.lhs_->ty_->compatible(&s.rhs_->ty_)) {
		std::cerr << "TypeError: Wrong type for rhs of ass.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_bin(bin &e)
{
	default_visitor::visit_bin(e);
	if (!e.lhs_->ty_->compatible(e.rhs_->ty_.get())) {
		std::cerr << "TypeError: Incompatible types in bin\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_cmp(cmp &e)
{
	default_visitor::visit_cmp(e);

	if (!e.lhs_->ty_->compatible(e.rhs_->ty_.get())) {
		std::cerr << "TypeError: Incompatible types in cmp\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_deref(deref &e)
{
	default_visitor::visit_deref(e);

	if (!e.e_->ty_->ptr_) {
		std::cerr << "Can't derefence non pointer type.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_addrof(addrof &e)
{
	default_visitor::visit_addrof(e);

	if (e.ty_->compatible(types::type::VOID)) {
		std::cerr << "Pointer to void are not supported.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_call(call &e)
{
	default_visitor::visit_call(e);

	for (size_t i = 0; i < e.fdec_->args_.size(); i++) {
		if (e.args_[i]->ty_->compatible(&e.fdec_->args_[i]->type_))
			continue;
		std::cerr << e.args_[i]->ty_->to_string() << '\n';
		std::cerr << e.fdec_->args_[i]->type_->to_string() << '\n';
		std::cerr << "TypeError: Wrong type for argument '"
			  << e.fdec_->args_[i]->name_ << "' of call to '"
			  << e.name_ << "'\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}

void tycheck_visitor::visit_memberaccess(memberaccess &e)
{
	default_visitor::visit_memberaccess(e);

	if (e.e_->ty_->ptr_) {
		std::cerr << "TypeError: Operator '.' on pointer.\n";
		COMPILATION_ERROR(utils::cfail::SEMA);
	}
}
} // namespace frontend::sema
