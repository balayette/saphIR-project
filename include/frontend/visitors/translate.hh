#pragma once

#include "ir/ir.hh"
#include "default-visitor.hh"
#include "utils/scoped.hh"
#include "frontend/ops.hh"
#include <unordered_map>
#include <vector>

namespace frontend::translate
{
class exp
{
      public:
	virtual ~exp() = default;

	virtual ir::tree::rexp un_ex() = 0;
	virtual ir::tree::rstm un_nx() = 0;
	virtual ir::tree::rstm un_cx(const utils::label &t,
				     const utils::label &f) = 0;
};

class cx : public exp
{
      public:
	cx(ops::cmpop op, ir::tree::rexp l, ir::tree::rexp r);

	ir::tree::rexp un_ex() override;
	ir::tree::rstm un_nx() override;
	ir::tree::rstm un_cx(const utils::label &t,
			     const utils::label &f) override;

      private:
	ops::cmpop op_;
	ir::tree::rexp l_;
	ir::tree::rexp r_;
};

class ex : public exp
{
      public:
	ex(ir::tree::rexp e);
	ir::tree::rexp un_ex() override;
	ir::tree::rstm un_nx() override;
	ir::tree::rstm un_cx(const utils::label &t,
			     const utils::label &f) override;

      private:
	ir::tree::rexp e_;
};

class nx : public exp
{
      public:
	nx(ir::tree::rstm s);
	ir::tree::rexp un_ex() override;
	ir::tree::rstm un_nx() override;
	ir::tree::rstm un_cx(const utils::label &t,
			     const utils::label &f) override;

      private:
	ir::tree::rstm s_;
};

class translate_visitor : public default_visitor
{
      public:
	void visit_ref(ref &e) override;
	void visit_num(num &e) override;
	void visit_call(call &e) override;
	void visit_bin(bin &e) override;
	void visit_cmp(cmp &e) override;
	void visit_forstmt(forstmt &s) override;
	void visit_ifstmt(ifstmt &s) override;
	void visit_ass(ass &s) override;
	void visit_decs(decs &s) override;
	void visit_vardec(vardec &s) override;
	void visit_globaldec(globaldec &s) override;
	void visit_ret(ret &s) override;
	void visit_str_lit(str_lit &e) override;
	void visit_fundec(fundec &s) override;
	void visit_deref(deref &e) override;
	void visit_addrof(addrof &e) override;

	utils::ref<exp> ret_;
	utils::scoped_var<utils::label> ret_lbl_;
	std::unordered_map<utils::label, str_lit> str_lits_;
	std::vector<mach::fun_fragment> funs_;
	std::vector<ir::tree::rstm> init_funs_;
	utils::ref<mach::fun_fragment> init_fun_;
};

} // namespace frontend::translate
