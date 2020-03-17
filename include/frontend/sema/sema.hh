#pragma once
#include "frontend/visitors/default-visitor.hh"
#include "utils/scoped.hh"
#include "utils/symbol.hh"
#include "frontend/stmt.hh"
#include "frontend/exp.hh"

namespace frontend::sema
{
class binding_visitor : public default_visitor
{
      public:
	binding_visitor();

	virtual void visit_decs(decs &s) override;
	virtual void visit_memberdec(memberdec &s) override;
	virtual void visit_structdec(structdec &s) override;
	virtual void visit_globaldec(globaldec &s) override;
	virtual void visit_locdec(locdec &s) override;
	virtual void visit_funprotodec(funprotodec &s) override;
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_ret(ret &s) override;
	virtual void visit_ifstmt(ifstmt &s) override;
	virtual void visit_forstmt(forstmt &s) override;

	virtual void visit_paren(paren &e) override;
	virtual void visit_braceinit(braceinit &e) override;
	virtual void visit_bin(bin &e) override;
	virtual void visit_ref(ref &e) override;
	virtual void visit_deref(deref &e) override;
	virtual void visit_addrof(addrof &e) override;
	virtual void visit_call(call &e) override;
	virtual void visit_memberaccess(memberaccess &e) override;
	virtual void visit_arrowaccess(arrowaccess &e) override;

      private:
	void new_scope();
	void end_scope();
	utils::ref<types::ty> get_type(utils::ref<types::ty> t);

	utils::scoped_map<symbol, funprotodec *> fmap_;
	utils::scoped_map<symbol, vardec *> vmap_;
	utils::scoped_map<symbol, utils::ref<types::ty>> tmap_;
	utils::scoped_ptr<fundec *> cfunc_;
};

class escapes_visitor : public default_visitor
{
      public:
	virtual void visit_addrof(addrof &e) override;
	virtual void visit_locdec(locdec &e) override;
};

class frame_visitor : public default_visitor
{
      public:
	virtual void visit_funprotodec(funprotodec &s) override;
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_globaldec(globaldec &s) override;
	virtual void visit_locdec(locdec &s) override;
	virtual void visit_call(call &s) override;

      private:
	mach::frame *cframe_;
};
} // namespace frontend::sema
