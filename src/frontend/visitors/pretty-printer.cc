#include "frontend/visitors/pretty-printer.hh"
namespace frontend
{
pretty_printer::pretty_printer(std::ostream &os)
    : os_(os), lvl_(0), new_line_(true), in_for_(false)
{
}

void pretty_printer::visit_decs(decs &s)
{
	for (auto d : s.decs_) {
		d->accept(*this);
		os_ << '\n';
	}
}
void pretty_printer::visit_memberdec(memberdec &s)
{
	indent() << s.type_->to_string() << ' ' << s.name_ << ";";
}

void pretty_printer::visit_structdec(structdec &s)
{
	indent() << "struct " << s.name_ << " {\n";
	lvl_++;
	for (auto mem : s.members_) {
		new_line_ = true;
		mem->accept(*this);
		os_ << '\n';
	}
	lvl_--;
	indent() << "}\n";
}

void pretty_printer::visit_globaldec(globaldec &s)
{
	indent() << "let " << s << " = ";
	s.rhs_->accept(*this);
	os_ << ';';
}

void pretty_printer::visit_locdec(locdec &s)
{
	indent() << "let " << s << " = ";

	s.rhs_->accept(*this);

	os_ << ';';
}

void pretty_printer::visit_funprotodec(funprotodec &s)
{
	os_ << "fun " << s.name_ << '(';

	for (auto it = s.args_.begin(); it != s.args_.end(); it++) {
		os_ << **it;
		if (it != s.args_.end() - 1)
			os_ << ", ";
	}

	os_ << ") " << s.type_->to_string();

	if (s.variadic_)
		os_ << " variadic";
	os_ << ";\n";
}

void pretty_printer::visit_fundec(fundec &s)
{
	os_ << "fun " << s.name_ << '(';

	for (auto it = s.args_.begin(); it != s.args_.end(); it++) {
		os_ << **it;
		if (it != s.args_.end() - 1)
			os_ << ", ";
	}

	os_ << ") " << s.type_->to_string() << " {\n";

	lvl_++;
	for (auto b : s.body_) {
		new_line_ = true;
		b->accept(*this);
		os_ << '\n';
	}
	lvl_--;

	os_ << "}\n";
}

void pretty_printer::visit_sexp(sexp &s)
{
	indent();
	s.e_->accept(*this);
	os_ << ';';
}

void pretty_printer::visit_ret(ret &s)
{
	indent() << "return";
	if (s.e_) {
		os_ << ' ';
		s.e_->accept(*this);
	}
	os_ << ";";
}

void pretty_printer::visit_ifstmt(ifstmt &s)
{
	indent() << "if (";
	s.cond_->accept(*this);
	os_ << ")\n";

	lvl_++;
	for (auto b : s.ibody_) {
		new_line_ = true;
		b->accept(*this);
		os_ << '\n';
	}
	lvl_--;

	if (s.ebody_.size() > 0) {
		new_line_ = true;
		indent() << "else\n";
		lvl_++;
		for (auto b : s.ebody_) {
			new_line_ = true;
			b->accept(*this);
			os_ << '\n';
		}
		lvl_--;
	}

	new_line_ = true;
	indent() << "fi";
}

void pretty_printer::visit_forstmt(forstmt &s)
{
	indent() << "for (";
	s.init_->accept(*this);
	os_ << " ";
	s.cond_->accept(*this);
	os_ << "; ";
	in_for_ = true;
	s.action_->accept(*this);
	in_for_ = false;
	os_ << ")\n";

	lvl_++;
	for (auto b : s.body_) {
		new_line_ = true;
		b->accept(*this);
		os_ << '\n';
	}

	lvl_--;
	new_line_ = true;
	indent() << "rof";
}

void pretty_printer::visit_ass(ass &s)
{
	indent();
	s.lhs_->accept(*this);
	os_ << " = ";
	s.rhs_->accept(*this);
	if (!in_for_)
		os_ << ";";
}

void pretty_printer::visit_inline_asm(inline_asm &s)
{
	indent();
	os_ << "__asm(\n";
	lvl_++;

	new_line_ = true;
	indent();
	os_ << '(';
	for (size_t i = 0; i < s.reg_in_.size(); i++) {
		os_ << '"' << s.reg_in_[i].regstr_ << "\": ";
		s.reg_in_[i].e_->accept(*this);
		if (i != s.reg_in_.size() - 1)
			os_ << ", ";
	}
	os_ << "),\n";

	new_line_ = true;
	indent();
	os_ << '(';
	for (size_t i = 0; i < s.reg_out_.size(); i++) {
		os_ << '"' << s.reg_out_[i].regstr_ << "\": ";
		s.reg_out_[i].e_->accept(*this);
		if (i != s.reg_out_.size() - 1)
			os_ << ", ";
	}
	os_ << "),\n";

	new_line_ = true;
	indent();
	os_ << '(';
	for (size_t i = 0; i < s.reg_clob_.size(); i++) {
		os_ << '"' << s.reg_clob_[i] << '"';
		if (i != s.reg_out_.size() - 1)
			os_ << ", ";
	}
	os_ << "),\n";

	new_line_ = true;
	lvl_--;
	indent();
	os_ << "{\n";

	lvl_++;
	for (size_t i = 0; i < s.lines_.size(); i++) {
		new_line_ = true;
		indent();
		os_ << '"' << s.lines_[i] << '"';
		if (i != s.lines_.size())
			os_ << ",\n";
	}

	new_line_ = true;
	lvl_--;
	indent();
	os_ << "};";
}

/* expressions */
void pretty_printer::visit_braceinit(braceinit &e)
{
	os_ << "{ ";
	for (auto it = e.exps_.begin(); it != e.exps_.end(); ++it) {
		(*it)->accept(*this);
		if (it != e.exps_.end() - 1)
			os_ << ",";
		os_ << " ";
	}
	os_ << "}";
}

void pretty_printer::visit_paren(paren &e)
{
	os_ << '(';
	e.e_->accept(*this);
	os_ << ')';
}

void pretty_printer::visit_cast(cast &e)
{
	os_ << "__cast(" << e.ty_->to_string() << ", ";
	e.e_->accept(*this);
	os_ << ')';
}

void pretty_printer::visit_bin(bin &e)
{
	e.lhs_->accept(*this);
	os_ << " " << binop_to_string(e.op_) << " ";
	e.rhs_->accept(*this);
}

void pretty_printer::visit_unary(unary &e)
{
	os_ << unaryop_to_string(e.op_);
	e.e_->accept(*this);
}

void pretty_printer::visit_cmp(cmp &e)
{
	e.lhs_->accept(*this);
	os_ << " " << cmpop_to_string(e.op_) << " ";
	e.rhs_->accept(*this);
}

void pretty_printer::visit_num(num &e) { os_ << e.value_; }

void pretty_printer::visit_ref(ref &e)
{
	if (e.dec_) {
		os_ << e.dec_->name_;
		if (e.dec_->escapes_)
			os_ << "^";
	} else
		os_ << e.name_;
}

void pretty_printer::visit_deref(deref &e)
{
	os_ << '*';
	e.e_->accept(*this);
}

void pretty_printer::visit_addrof(addrof &e)
{
	os_ << '&';
	e.e_->accept(*this);
}

void pretty_printer::visit_call(call &e)
{
	e.f_->accept(*this);
	os_ << '(';

	for (auto it = e.args_.begin(); it != e.args_.end(); it++) {
		(*it)->accept(*this);
		if (it != e.args_.end() - 1)
			os_ << ", ";
	}

	os_ << ')';
}
std::ostream &pretty_printer::indent()
{
	if (new_line_) {
		for (unsigned i = 0; i < lvl_; i++)
			os_ << "    ";
		new_line_ = false;
	}
	return os_;
}

void pretty_printer::visit_str_lit(str_lit &e) { os_ << '"' << e.str_ << '"'; }

void pretty_printer::visit_memberaccess(memberaccess &e)
{
	e.e_->accept(*this);
	os_ << "." << e.member_;
}

void pretty_printer::visit_arrowaccess(arrowaccess &e)
{
	e.e_->accept(*this);
	os_ << "->" << e.member_;
}

void pretty_printer::visit_subscript(subscript &e)
{
	e.base_->accept(*this);
	os_ << '[';
	e.index_->accept(*this);
	os_ << ']';
}
} // namespace frontend
