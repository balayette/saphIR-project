#pragma once

#include "mach/frame.hh"
#include "ass/instr.hh"
#include "ir/ir.hh"
#include "ir/visitors/default-ir-visitor.hh"
#include <vector>

namespace mach
{
std::vector<assem::rinstr> codegen(mach::frame &f, ir::tree::rnodevec instrs);

struct generator : public ir::default_ir_visitor {
	void emit(assem::rinstr i);

	void visit_cnst(ir::tree::cnst &) override;
	void visit_temp(ir::tree::temp &) override;
	void visit_binop(ir::tree::binop &) override;
	void visit_mem(ir::tree::mem &) override;
	void visit_call(ir::tree::call &n) override;
	void visit_move(ir::tree::move &) override;
	void visit_name(ir::tree::name &n) override;
	void visit_jump(ir::tree::jump &) override;
	void visit_cjump(ir::tree::cjump &) override;
	void visit_label(ir::tree::label &) override;

	std::vector<assem::rinstr> instrs_;
	utils::temp ret_;
};
} // namespace mach
