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

	virtual backend::tree::rexp un_ex() = 0;
	virtual backend::tree::rstm un_nx() = 0;
	virtual backend::tree::rstm un_cx(const temp::label &t,
					  const temp::label &f) = 0;
};

class cx : public exp
{
      public:
	cx(ops::cmpop op, backend::tree::rexp l, backend::tree::rexp r);

	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	ops::cmpop op_;
	backend::tree::rexp l_;
	backend::tree::rexp r_;
};

class ex : public exp
{
      public:
	ex(backend::tree::rexp e);
	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::rexp e_;
};

class nx : public exp
{
      public:
	nx(backend::tree::rstm s);
	backend::tree::rexp un_ex() override;
	backend::tree::rstm un_nx() override;
	backend::tree::rstm un_cx(const temp::label &t,
				  const temp::label &f) override;

      private:
	backend::tree::rstm s_;
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
	void visit_vardec(vardec &s) override;
	void visit_ret(ret &s) override;
	void visit_str_lit(str_lit &e) override;
	void visit_fundec(fundec &s) override;
	void visit_deref(deref &e) override;
	void visit_addrof(addrof &e) override;

	utils::ref<exp> ret_;
	utils::scoped_var<::temp::label> ret_lbl_;
	std::unordered_map<::temp::label, str_lit> str_lits_;
	std::vector<frame::fun_fragment> funs_;
};

} // namespace frontend::translate
