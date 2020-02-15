#include "frontend/visitors/pretty-printer.hh"
namespace frontend
{
pretty_printer::pretty_printer(std::ostream &os)
    : os_(os), lvl_(0), new_line_(true)
{
}

void pretty_printer::visit_decs(decs &s)
{
	for (auto *d : s.decs_) {
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
	for (auto *mem : s.members_) {
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
	for (auto *b : s.body_) {
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
	for (auto *b : s.ibody_) {
		new_line_ = true;
		b->accept(*this);
		os_ << '\n';
	}
	lvl_--;

	if (s.ebody_.size() > 0) {
		new_line_ = true;
		indent() << "else\n";
		lvl_++;
		for (auto *b : s.ebody_) {
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
	s.action_->accept(*this);
	os_ << ")\n";

	lvl_++;
	for (auto *b : s.body_) {
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
}

/* expressions */
void pretty_printer::visit_bin(bin &e)
{
	e.lhs_->accept(*this);
	os_ << " " << binop_to_string(e.op_) << " ";
	e.rhs_->accept(*this);
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
	if (e.fdec_)
		os_ << e.fdec_->name_;
	else
		os_ << e.name_;
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
} // namespace frontend
