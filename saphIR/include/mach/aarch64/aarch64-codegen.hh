#pragma once

#include "mach/codegen.hh"
#include "mach/aarch64/aarch64-target.hh"

namespace mach::aarch64
{
struct generator : public ir::default_ir_visitor {
	void emit(assem::rinstr i);

	void visit_cnst(ir::tree::cnst &) override;
	void visit_temp(ir::tree::temp &) override;
	void visit_mem(ir::tree::mem &) override;
	void visit_sext(ir::tree::sext &) override;
	void visit_zext(ir::tree::zext &) override;
	void visit_call(ir::tree::call &n) override;
	void visit_cjump(ir::tree::cjump &) override;
	void visit_binop(ir::tree::binop &) override;
	void visit_unaryop(ir::tree::unaryop &) override;
	void visit_move(ir::tree::move &) override;
	void visit_name(ir::tree::name &n) override;
	void visit_jump(ir::tree::jump &) override;
	void visit_label(ir::tree::label &) override;
	void visit_asm_block(ir::tree::asm_block &) override;

	std::vector<assem::rinstr> instrs_;
	assem::temp ret_;

      private:
	bool opt_add(ir::tree::binop &add);
	bool opt_mul(ir::tree::binop &add);
};

struct aarch64_generator : public mach::asm_generator {
	aarch64_generator(mach::aarch64::aarch64_target &target)
	    : target_(target)
	{
	}

	assem::temp codegen(ir::tree::rnode instr) override;
	void codegen(ir::tree::rnodevec instrs) override;

	void emit(assem::rinstr &i) override;

	std::vector<assem::rinstr> output() override;

	mach::aarch64::aarch64_target &target_;

      private:
	std::vector<assem::rinstr> instrs_;
	generator g_;
};
} // namespace mach::aarch64
