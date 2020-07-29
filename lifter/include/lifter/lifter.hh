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
enum flag_op {
	CMP,
};

struct state {
	uint64_t regs[32];
	uint64_t flag_a;
	uint64_t flag_b;
	uint64_t flag_op;
};

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
	ir::tree::rexp translate_mem_op(arm64_op_mem r);
	ir::tree::rstm set_state_field(const std::string &name,
				       ir::tree::rexp val);
	ir::tree::rexp get_state_field(const std::string &name);
	ir::tree::rstm set_cmp_values(ir::tree::rexp lhs, ir::tree::rexp rhs,
				      enum flag_op op);
	ir::tree::rexp shift(ir::tree::rexp exp, arm64_shifter shifter,
			     unsigned value);
	ir::tree::rstm next_address(ir::tree::rexp addr);

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
	ir::tree::rstm arm64_handle_RET(const disas_insn &insn);
	ir::tree::rstm arm64_handle_BL(const disas_insn &insn);
	ir::tree::rstm arm64_handle_CMP(const disas_insn &insn);
	ir::tree::rstm arm64_handle_CMP_imm(cs_arm64_op xn, cs_arm64_op imm);
	ir::tree::rstm arm64_handle_B(const disas_insn &insn);
	ir::tree::rstm arm64_handle_STP(const disas_insn &insn);
	ir::tree::rstm arm64_handle_STP_post(cs_arm64_op xt1, cs_arm64_op xt2,
					     cs_arm64_op xn, cs_arm64_op imm);
	ir::tree::rstm arm64_handle_STP_pre(cs_arm64_op xt1, cs_arm64_op xt2,
					    cs_arm64_op xn);
	ir::tree::rstm arm64_handle_STP_base_offset(cs_arm64_op xt1,
						    cs_arm64_op xt2,
						    cs_arm64_op xn);
	ir::tree::rstm arm64_handle_LDP(const disas_insn &insn);
	ir::tree::rstm arm64_handle_LDP_post(cs_arm64_op xt1, cs_arm64_op xt2,
					     cs_arm64_op xn, cs_arm64_op imm);
	ir::tree::rstm arm64_handle_LDP_pre(cs_arm64_op xt1, cs_arm64_op xt2,
					    cs_arm64_op xn);
	ir::tree::rstm arm64_handle_LDP_base_offset(cs_arm64_op xt1,
						    cs_arm64_op xt2,
						    cs_arm64_op xn);
	ir::tree::rstm arm64_handle_ADRP(const disas_insn &insn);
	ir::tree::rstm arm64_handle_STR(const disas_insn &insn);
	ir::tree::rstm arm64_handle_STR_reg(cs_arm64_op xt, cs_arm64_op dst);
	ir::tree::rstm arm64_handle_STR_pre(cs_arm64_op xt, cs_arm64_op dst);
	ir::tree::rstm arm64_handle_STR_base_offset(cs_arm64_op xt,
						    cs_arm64_op dst);
	ir::tree::rstm arm64_handle_STR_post(cs_arm64_op xt, cs_arm64_op dst,
					     cs_arm64_op imm);

	utils::ref<mach::amd64::amd64_target> amd_target_;
	utils::ref<mach::aarch64::aarch64_target> arm_target_;

	utils::ref<mach::access> bank_;
	utils::ref<types::struct_ty> bank_type_;
	utils::ref<types::ty> bb_type_;
};
} // namespace lifter
