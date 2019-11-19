#pragma once
#include "default-visitor.hh"
#include "scoped.hh"
#include "symbol.hh"
#include "stmt.hh"
#include "exp.hh"

namespace sema
{
class binding_visitor : public default_visitor
{
      public:
	virtual void visit_decs(decs &s) override;
	virtual void visit_vardec(vardec &s) override;
	virtual void visit_argdec(argdec &s) override;
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_ret(ret &s) override;
	virtual void visit_ifstmt(ifstmt &s) override;
	virtual void visit_forstmt(forstmt &s) override;
	virtual void visit_ass(ass &s) override;

	virtual void visit_bin(bin &e) override;
	virtual void visit_cmp(cmp &e) override;
	virtual void visit_ref(ref &e) override;
	virtual void visit_deref(deref &e) override;
	virtual void visit_addrof(addrof &e) override;
	virtual void visit_call(call &e) override;

      private:
	void new_scope();
	void end_scope();

	scoped_map<symbol, fundec *> fmap_;
	scoped_map<symbol, dec *> vmap_;
	scoped_ptr<fundec *> cfunc_;
};

class escapes_visitor : public default_visitor
{
      public:
	virtual void visit_addrof(addrof &e) override;
};

class frame_visitor : public default_visitor
{
      public:
	virtual void visit_fundec(fundec &s) override;
	virtual void visit_vardec(vardec &s) override;

      private:
	frame::frame *cframe_;
};
} // namespace sema
