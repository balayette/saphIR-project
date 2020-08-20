#pragma once

#include "ir/ir.hh"
#include "default-visitor.hh"
#include "utils/scoped.hh"
#include "ir/ops.hh"
#include "mach/target.hh"
#include <unordered_map>
#include <vector>

namespace frontend::translate
{
using namespace ir::tree;

class translate_visitor : public default_visitor
{
      public:
	translate_visitor(mach::target &target) : target_(target) {}
	void visit_ref(ref &e) override;
	void visit_num(num &e) override;
	void visit_call(call &e) override;
	void visit_cast(cast &e) override;
	void visit_bin(bin &e) override;
	void visit_unary(unary &e) override;
	void visit_cmp(cmp &e) override;
	void visit_forstmt(forstmt &s) override;
	void visit_ifstmt(ifstmt &s) override;
	void visit_ass(ass &s) override;
	void visit_inline_asm(inline_asm &s) override;
	void visit_decs(decs &s) override;
	void visit_locdec(locdec &s) override;
	void visit_globaldec(globaldec &s) override;
	void visit_ret(ret &s) override;
	void visit_str_lit(str_lit &e) override;
	void visit_funprotodec(funprotodec &s) override;
	void visit_fundec(fundec &s) override;
	void visit_deref(deref &e) override;
	void visit_addrof(addrof &e) override;
	void visit_memberaccess(memberaccess &e) override;
	void visit_arrowaccess(arrowaccess &e) override;
	void visit_braceinit(braceinit &e) override;
	void visit_subscript(subscript &e) override;

	utils::ref<meta_exp> struct_access(ir::tree::rexp lhs,
					   const symbol &member);
	utils::ref<meta_exp>
	braceinit_copy_to_struct(ir::tree::rexp lhs,
				 utils::ref<ir::tree::braceinit> rhs);
	utils::ref<meta_exp>
	braceinit_copy_to_array(ir::tree::rexp lhs,
				utils::ref<ir::tree::braceinit> rhs);
	utils::ref<meta_exp>
	braceinit_copy(ir::tree::rexp lhs, utils::ref<ir::tree::braceinit> rhs);
	utils::ref<meta_exp> struct_copy(ir::tree::rexp lhs,
					 ir::tree::rexp rhs);
	utils::ref<meta_exp> array_copy(ir::tree::rexp lhs, ir::tree::rexp rhs);
	utils::ref<meta_exp> copy(ir::tree::rexp lhs, ir::tree::rexp rhs);

	utils::ref<meta_exp> ret_;
	utils::scoped_var<utils::label> ret_lbl_;
	std::unordered_map<utils::label, str_lit> str_lits_;
	std::vector<mach::fun_fragment> funs_;
	std::vector<ir::tree::rstm> init_funs_;
	utils::ref<mach::fun_fragment> init_fun_;

	mach::target &target_;
};

} // namespace frontend::translate
