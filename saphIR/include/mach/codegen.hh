#pragma once

#include "ass/instr.hh"
#include "ir/ir.hh"
#include "ir/visitors/default-ir-visitor.hh"
#include <vector>

namespace mach
{
struct asm_generator {
	virtual ~asm_generator() = default;

	virtual assem::temp codegen(ir::tree::rnode instr) = 0;
	virtual void codegen(ir::tree::rnodevec instrs) = 0;

	virtual void emit(assem::rinstr &i) = 0;

	virtual std::vector<assem::rinstr> output() = 0;
};
} // namespace mach
