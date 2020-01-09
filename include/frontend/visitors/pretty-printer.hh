#pragma once
#include "default-visitor.hh"
#include "frontend/types.hh"
#include <iostream>
#include <string>

namespace frontend
{
class pretty_printer : public default_visitor
{
      public:
	pretty_printer(std::ostream &os);

	virtual void visit_decs(decs &s) override;
	virtual void visit_globaldec(globaldec &s) override;
	virtual void visit_vardec(vardec &s) override;
	virtual void visit_argdec(argdec &s) override;
	virtual void visit_funprotodec(funprotodec &s) override;
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_sexp(sexp &s) override;
	virtual void visit_ret(ret &s) override;
	virtual void visit_ifstmt(ifstmt &s) override;
	virtual void visit_forstmt(forstmt &s) override;
	virtual void visit_ass(ass &s) override;

	/* expressions */
	virtual void visit_bin(bin &e) override;
	virtual void visit_cmp(cmp &e) override;
	virtual void visit_num(num &e) override;
	virtual void visit_ref(ref &e) override;
	virtual void visit_deref(deref &e) override;
	virtual void visit_addrof(addrof &e) override;
	virtual void visit_call(call &e) override;
	virtual void visit_str_lit(str_lit &e) override;

      private:
	std::ostream &indent();

	std::ostream &os_;
	unsigned lvl_;
	bool new_line_;
};
} // namespace frontend
