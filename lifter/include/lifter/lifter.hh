#pragma once

#include <vector>
#include "mach/target.hh"
#include "mach/amd64/amd64-target.hh"
#include "mach/aarch64/aarch64-target.hh"
#include "ir/ir.hh"
#include "utils/ref.hh"
#include "lifter/disas.hh"

namespace lifter
{
class lifter
{
      public:
	lifter()
	    : amd_target_(new mach::amd64::amd64_target()),
	      arm_target_(new mach::aarch64::aarch64_target())
	{
	}

	std::vector<ir::tree::rstm> lift(const disas_bb &bb);

      private:
	ir::tree::rstm lift(const disas_insn &insn);
	ir::tree::temp *translate_gpr(arm64_reg r);
	ir::tree::rexp shift(ir::tree::rexp exp, arm64_shifter shifter,
			     unsigned value);

	ir::tree::rstm arm64_handle_MOV_reg_reg(const disas_insn &insn);
	ir::tree::rstm arm64_handle_MOV(const disas_insn &insn);
	ir::tree::rstm arm64_handle_MOVZ(const disas_insn &insn);
	ir::tree::rstm arm64_handle_ADD(const disas_insn &insn);
	ir::tree::rexp arm64_handle_ADD_imm(cs_arm64_op rn, cs_arm64_op imm);
	ir::tree::rexp arm64_handle_ADD_reg(cs_arm64_op rn, cs_arm64_op rm);

	utils::ref<mach::amd64::amd64_target> amd_target_;
	utils::ref<mach::aarch64::aarch64_target> arm_target_;

	utils::temp flags_;
};
} // namespace lifter
