#pragma once
#include "frontend/visitors/default-visitor.hh"
#include "utils/scoped.hh"
#include "utils/symbol.hh"
#include "frontend/stmt.hh"
#include "frontend/exp.hh"


namespace frontend::sema
{
class tycheck_visitor : public default_visitor
{
      public:
	tycheck_visitor();
	virtual void visit_globaldec(globaldec &s) override;
	virtual void visit_locdec(locdec &s) override;
	virtual void visit_funprotodec(funprotodec &s) override;
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_ifstmt(ifstmt &s) override;
	virtual void visit_forstmt(forstmt &s) override;
	virtual void visit_ret(ret &s) override;
	virtual void visit_ass(ass &s) override;
	virtual void visit_structdec(structdec &s) override;
	virtual void visit_memberdec(memberdec &s) override;

	virtual void visit_bin(bin &e) override;
	virtual void visit_cmp(cmp &e) override;
	virtual void visit_deref(deref &e) override;
	virtual void visit_addrof(addrof &e) override;
	virtual void visit_paren(paren &e) override;
	virtual void visit_call(call &e) override;
	virtual void visit_memberaccess(memberaccess &e) override;
	virtual void visit_arrowaccess(arrowaccess &e) override;
	virtual void visit_ref(ref &e) override;
	virtual void visit_braceinit(braceinit &e) override;

	utils::ref<types::ty> get_type(utils::ref<types::ty> t);
	utils::scoped_map<symbol, utils::ref<types::ty>> tmap_;
};
} // namespace frontend::sema
