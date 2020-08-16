#pragma once
#include "ir-visitor.hh"
#include "ir/ir.hh"
#include "mach/target.hh"

namespace ir
{
class ir_cloner_visitor : public ir_visitor
{
      public:
	ir_cloner_visitor(mach::target &target) : target_(target) {}
	virtual ~ir_cloner_visitor() = default;

	template <typename T> utils::ref<T> perform(const utils::ref<T> &n);

	virtual void visit_cnst(tree::cnst &) override;
	virtual void visit_braceinit(tree::braceinit &) override;
	virtual void visit_name(tree::name &) override;
	virtual void visit_temp(tree::temp &) override;
	virtual void visit_binop(tree::binop &) override;
	virtual void visit_unaryop(tree::unaryop &) override;
	virtual void visit_mem(tree::mem &) override;
	virtual void visit_call(tree::call &) override;
	virtual void visit_eseq(tree::eseq &) override;
	virtual void visit_sext(tree::sext &) override;
	virtual void visit_zext(tree::zext &) override;
	virtual void visit_move(tree::move &) override;
	virtual void visit_sexp(tree::sexp &) override;
	virtual void visit_jump(tree::jump &) override;
	virtual void visit_cjump(tree::cjump &) override;
	virtual void visit_seq(tree::seq &) override;
	virtual void visit_label(tree::label &) override;
	virtual void visit_asm_block(tree::asm_block &) override;

      protected:
	template <typename U, typename T>
	utils::ref<U> recurse(const utils::ref<T> &n);

	mach::target &target_;
	tree::rnode ret_;
};
} // namespace ir

#include "ir-cloner-visitor.hxx"
