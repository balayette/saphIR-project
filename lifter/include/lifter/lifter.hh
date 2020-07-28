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
	lifter();
	mach::fun_fragment lift(const disas_bb &bb);

	mach::amd64::amd64_target &amd64_target() { return *amd_target_; }
	mach::aarch64::aarch64_target &aarch64_target() { return *arm_target_; }

      private:
	ir::tree::rstm lift(const disas_insn &insn);
	ir::tree::rexp translate_gpr(arm64_reg r);
	ir::tree::rexp shift(ir::tree::rexp exp, arm64_shifter shifter,
			     unsigned value);

	ir::tree::rstm arm64_handle_MOV_reg_reg(const disas_insn &insn);
	ir::tree::rstm arm64_handle_MOV(const disas_insn &insn);
	ir::tree::rstm arm64_handle_MOVZ(const disas_insn &insn);
	ir::tree::rstm arm64_handle_ADD(const disas_insn &insn);
	ir::tree::rexp arm64_handle_ADD_imm(cs_arm64_op rn, cs_arm64_op imm);
	ir::tree::rexp arm64_handle_ADD_reg(cs_arm64_op rn, cs_arm64_op rm);
	ir::tree::rstm arm64_handle_LDR(const disas_insn &insn);
	ir::tree::rstm arm64_handle_LDR_imm(cs_arm64_op xt, cs_arm64_op label);
	ir::tree::rstm arm64_handle_LDR_reg(cs_arm64_op xt, cs_arm64_op reg);
	ir::tree::rstm arm64_handle_MOVK(const disas_insn &insn);

	utils::ref<mach::amd64::amd64_target> amd_target_;
	utils::ref<mach::aarch64::aarch64_target> arm_target_;

	utils::ref<mach::access> bank_;
	utils::ref<types::ty> bank_type_;
	utils::ref<types::ty> bb_type_;
};
} // namespace lifter
