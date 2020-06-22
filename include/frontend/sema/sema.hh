#pragma once
#include "frontend/visitors/default-visitor.hh"
#include "utils/scoped.hh"
#include "utils/symbol.hh"
#include "mach/target.hh"
#include "frontend/stmt.hh"
#include "frontend/exp.hh"

namespace frontend::sema
{
class binding_visitor : public default_visitor
{
      public:
	virtual void visit_globaldec(globaldec &s) override;
	virtual void visit_locdec(locdec &s) override;
	virtual void visit_funprotodec(funprotodec &s) override;
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_ret(ret &s) override;
	virtual void visit_ifstmt(ifstmt &s) override;
	virtual void visit_forstmt(forstmt &s) override;

	virtual void visit_ref(ref &e) override;

      private:
	void new_scope();
	void end_scope();

	utils::scoped_map<symbol, funprotodec *> fmap_;
	utils::scoped_map<symbol, vardec *> vmap_;
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
	frame_visitor(mach::target &target) : target_(target) {}
	virtual void visit_funprotodec(funprotodec &s) override;
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_globaldec(globaldec &s) override;
	virtual void visit_locdec(locdec &s) override;
	virtual void visit_call(call &s) override;

      private:
        utils::ref<mach::frame> cframe_;
	mach::target &target_;
};
} // namespace frontend::sema
