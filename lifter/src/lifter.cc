#include "lifter/lifter.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "lifter/disas.hh"
#include "mach/aarch64/aarch64-common.hh"
#include "utils/assert.hh"
#include "fmt/format.h"

#define HANDLER(Kind)                                                          \
	case ARM64_INS_##Kind:                                                 \
		return arm64_handle_##Kind(insn)

namespace lifter
{
bool is_gpr(arm64_reg r)
{
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30)
		return true;
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28)
		return true;
	return r == ARM64_REG_X29 || r == ARM64_REG_X30 || r == ARM64_REG_SP;
}

mach::aarch64::regs creg_to_reg(arm64_reg r)
{
	if (r >= ARM64_REG_W0 && r <= ARM64_REG_W30)
		return static_cast<mach::aarch64::regs>(mach::aarch64::regs::R0
							+ (r - ARM64_REG_W0));

	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28)
		return creg_to_reg(static_cast<arm64_reg>(
			ARM64_REG_W0 + (r - ARM64_REG_X0)));
	if (r == ARM64_REG_X29)
		return creg_to_reg(ARM64_REG_W29);
	if (r == ARM64_REG_X30)
		return creg_to_reg(ARM64_REG_W30);
	if (r == ARM64_REG_SP)
		return mach::aarch64::regs::SP;

	UNREACHABLE("Register not supported");
}

ir::tree::rstm lifter::set_state_field(const std::string &name,
				       ir::tree::rexp val)
{
	return amd_target_->make_move(
		amd_target_->make_mem(amd_target_->make_binop(
			ops::binop::PLUS, bank_->exp(),
			amd_target_->make_cnst(bank_type_->member_offset(name)),
			new types::pointer_ty(amd_target_->gpr_type()))),
		val);
}

ir::tree::rexp lifter::get_state_field(const std::string &name)
{
	return amd_target_->make_mem(amd_target_->make_binop(
		ops::binop::PLUS, bank_->exp(),
		amd_target_->make_cnst(bank_type_->member_offset(name)),
		new types::pointer_ty(amd_target_->gpr_type())));
}

ir::tree::rexp lifter::translate_gpr(arm64_reg r)
{
	auto reg = creg_to_reg(r);
	unsigned sz = r >= ARM64_REG_W0 && r <= ARM64_REG_W30 ? 4 : 8;

	ir::tree::rexp dst = amd_target_->make_binop(
		ops::binop::PLUS, bank_->exp(), amd_target_->make_cnst(8 * reg),
		new types::pointer_ty(new types::builtin_ty(
			types::type::INT, sz, types::signedness::UNSIGNED,
			*arm_target_)));

	return amd_target_->make_mem(dst);
}

ir::tree::rexp lifter::shift(ir::tree::rexp exp, arm64_shifter shifter,
			     unsigned value)
{
	switch (shifter) {
	case ARM64_SFT_INVALID:
		return exp;
	case ARM64_SFT_LSL:
		return amd_target_->make_binop(ops::binop::BITLSHIFT, exp,
					       amd_target_->make_cnst(value),
					       arm_target_->integer_type());
	default:
		UNREACHABLE("Unhandled shift");
	}
}

ir::tree::rstm lifter::arm64_handle_MOV_reg_reg(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	arm64_reg dst = mach_det->operands[0].reg;
	arm64_reg src = mach_det->operands[1].reg;
	ASSERT(is_gpr(dst) && is_gpr(src), "Only GPR moves");

	return amd_target_->make_move(translate_gpr(dst), translate_gpr(src));
}

ir::tree::rstm lifter::arm64_handle_MOV(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	ASSERT(mach_det->op_count == 2, "Unimplemented form");

	cs_arm64_op dst = mach_det->operands[0];
	cs_arm64_op src = mach_det->operands[1];

	if (dst.type == ARM64_OP_REG && src.type == ARM64_OP_REG)
		return arm64_handle_MOV_reg_reg(insn);

	UNREACHABLE("Unimplemented MOV");
}

ir::tree::rstm lifter::arm64_handle_MOVZ(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	ASSERT(mach_det->op_count == 2, "Unimplemented form");

	cs_arm64_op rd = mach_det->operands[0];
	cs_arm64_op imm = mach_det->operands[1];
	ASSERT(rd.type == ARM64_OP_REG && imm.type == ARM64_OP_IMM,
	       "Wrong movz operands");

	return amd_target_->make_move(translate_gpr(rd.reg),
				      shift(amd_target_->make_cnst(imm.imm),
					    imm.shift.type, imm.shift.value));
}

ir::tree::rexp lifter::arm64_handle_ADD_imm(cs_arm64_op rn, cs_arm64_op imm)
{
	return amd_target_->make_binop(ops::binop::PLUS, translate_gpr(rn.reg),
				       shift(amd_target_->make_cnst(imm.imm),
					     imm.shift.type, imm.shift.value),
				       arm_target_->integer_type());
}

ir::tree::rexp lifter::arm64_handle_ADD_reg(cs_arm64_op rn, cs_arm64_op rm)
{
	return amd_target_->make_binop(
		ops::binop::PLUS, translate_gpr(rn.reg),
		shift(translate_gpr(rm.reg), rm.shift.type, rm.shift.value),
		arm_target_->integer_type());
}

ir::tree::rstm lifter::arm64_handle_ADD(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	ASSERT(mach_det->op_count == 3, "Impossible operand count");

	cs_arm64_op rd = mach_det->operands[0];
	cs_arm64_op rn = mach_det->operands[1];
	ASSERT(rd.type == ARM64_OP_REG && rn.type == ARM64_OP_REG,
	       "Wrong operands");

	cs_arm64_op m = mach_det->operands[2];
	auto op = m.type == ARM64_OP_IMM ? arm64_handle_ADD_imm(rn, m)
					 : arm64_handle_ADD_reg(rn, m);

	return amd_target_->make_move(translate_gpr(rd.reg), op);
}

ir::tree::rstm lifter::arm64_handle_LDR_imm(cs_arm64_op xt, cs_arm64_op imm)
{
	return amd_target_->make_move(translate_gpr(xt.reg),
				      amd_target_->make_cnst(imm.imm));
}

ir::tree::rstm lifter::arm64_handle_LDR_reg(cs_arm64_op xt, cs_arm64_op reg)
{
	auto dest = translate_gpr(xt.reg);
	auto src = translate_gpr(reg.reg);
	src->ty_ = new types::pointer_ty(dest->ty_);

	return amd_target_->make_move(dest, amd_target_->make_mem(src));
}

ir::tree::rstm lifter::arm64_handle_LDR(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();

	cs_arm64_op xt = mach_det->operands[0];
	cs_arm64_op base = mach_det->operands[1];
	if (base.type == ARM64_OP_IMM)
		return arm64_handle_LDR_imm(xt, base);

	if (mach_det->op_count == 2)
		return arm64_handle_LDR_reg(xt, base);

	UNREACHABLE("Unimplemented LDR form");
}

ir::tree::rstm lifter::arm64_handle_MOVK(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	cs_arm64_op xd = mach_det->operands[0];
	cs_arm64_op imm = mach_det->operands[1];

	auto dest = translate_gpr(xd.reg);
	auto cnst = amd_target_->make_cnst(imm.imm);

	return amd_target_->make_move(
		dest, amd_target_->make_binop(
			      ops::binop::BITOR, dest,
			      shift(cnst, imm.shift.type, imm.shift.value),
			      dest->ty_));
}

ir::tree::rstm lifter::next_address(ir::tree::rexp addr)
{
	return amd_target_->make_move(
		amd_target_->make_temp(amd_target_->rv(),
				       amd_target_->gpr_type()),
		addr);
}

ir::tree::rstm lifter::arm64_handle_RET(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto xn = mach_det->op_count == 0 ? ARM64_REG_X30
					  : mach_det->operands[0].reg;

	return next_address(translate_gpr(xn));
}

ir::tree::rstm lifter::arm64_handle_BL(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto imm = mach_det->operands[0];

	return amd_target_->make_seq({
		amd_target_->make_move(
			translate_gpr(ARM64_REG_X30),
			amd_target_->make_cnst(insn.address() + 4)),
		amd_target_->make_move(
			amd_target_->make_temp(amd_target_->rv(),
					       amd_target_->gpr_type()),
			amd_target_->make_cnst(imm.imm)),
	});
}

ir::tree::rstm lifter::set_cmp_values(ir::tree::rexp lhs, ir::tree::rexp rhs,
				      enum flag_op op)
{
	return amd_target_->make_seq({
		set_state_field("flag_a", lhs),
		set_state_field("flag_b", rhs),
		set_state_field("flag_op", amd_target_->make_cnst(op)),
	});
}

ir::tree::rstm lifter::arm64_handle_CMP_imm(cs_arm64_op xn, cs_arm64_op imm)
{
	return set_cmp_values(translate_gpr(xn.reg),
			      shift(amd_target_->make_cnst(imm.imm),
				    imm.shift.type, imm.shift.value),
			      flag_op::CMP);
}

ir::tree::rstm lifter::arm64_handle_CMP(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto xn = mach_det->operands[0];
	auto other = mach_det->operands[1];
	if (other.type == ARM64_OP_IMM)
		return arm64_handle_CMP_imm(xn, other);

	UNREACHABLE("Unimplemented cmp form");
}

ir::tree::rstm lifter::arm64_handle_B(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto lbl = mach_det->operands[0];
	ASSERT(lbl.type == ARM64_OP_IMM, "only branch to labels");

	if (mach_det->cc == ARM64_CC_INVALID || mach_det->cc == ARM64_CC_AL
	    || mach_det->cc == ARM64_CC_NV) {
		return next_address(amd_target_->make_cnst(lbl.imm));
	}

	auto fail_addr = insn.address() + 4;
	auto ok_addr = lbl.imm;

	auto fail_label = make_unique("fail");
	auto ok_label = make_unique("ok");
	auto end_label = make_unique("end");

	if (mach_det->cc == ARM64_CC_EQ) {
		return amd_target_->make_seq({
			amd_target_->make_cjump(ops::cmpop::EQ,
						get_state_field("flag_a"),
						get_state_field("flag_b"),
						ok_label, fail_label),
			amd_target_->make_label(ok_label),
			next_address(amd_target_->make_cnst(ok_addr)),
			amd_target_->make_jump(
				amd_target_->make_name(end_label), {end_label}),
			amd_target_->make_label(fail_label),
			next_address(amd_target_->make_cnst(fail_addr)),
			amd_target_->make_label(end_label),
		});
	}

	UNREACHABLE("Unhandled B form");
}

ir::tree::rstm lifter::lift(const disas_insn &insn)
{
	switch (insn.id()) {
		HANDLER(MOV);
		HANDLER(MOVZ);
		HANDLER(ADD);
		HANDLER(LDR);
		HANDLER(MOVK);
		HANDLER(RET);
		HANDLER(BL);
		HANDLER(CMP);
		HANDLER(B);
	default:
		fmt::print("Unimplemented instruction {} ({})\n", insn.as_str(),
			   insn.insn_name());
		UNREACHABLE("Unimplemented instruction");
	}
}

mach::fun_fragment lifter::lift(const disas_bb &bb)
{
	std::vector<ir::tree::rstm> ret;
	ir::ir_pretty_printer pir(std::cout);

	auto frame = amd_target_->make_frame(
		fmt::format("bb_{x}", bb.address()), {false},
		{new types::pointer_ty(bank_type_)}, true);
	bank_ = frame->formals()[0];

	const auto &insns = bb.insns();
	for (size_t i = 0; i < insns.size(); i++) {
		disas_insn ins = insns[i];
		std::cout << "Lifting instruction " << ins.as_str() << '\n';
		auto r = lift(ins);
		r->accept(pir);
		ret.push_back(r);
	}

	auto body = amd_target_->make_seq(ret);
	auto ret_lbl = make_unique("ret");
	return mach::fun_fragment(frame->proc_entry_exit_1(body, ret_lbl),
				  frame, ret_lbl, make_unique("epi"));
}

lifter::lifter()
    : amd_target_(new mach::amd64::amd64_target()),
      arm_target_(new mach::aarch64::aarch64_target())
{
	std::vector<symbol> names;
	std::vector<utils::ref<types::ty>> types;

	for (size_t i = 0; i < 32; i++) {
		names.push_back(fmt::format("r{}", i));
		types.push_back(arm_target_->gpr_type());
	}

	bank_type_ = new types::struct_ty(
		"state",
		{
			"regs",
			"flag_a",
			"flag_b",
			"flag_op",
		},
		{
			new types::array_ty(amd_target_->gpr_type(), 32),
			amd_target_->gpr_type(), // flag_a
			amd_target_->gpr_type(), // flag_b
			amd_target_->gpr_type(), // flag_op
		});

	// fun basic_block(state* bank) int<8>
	bb_type_ =
		new types::fun_ty(amd_target_->gpr_type(),
				  {new types::pointer_ty(bank_type_)}, false);
}
} // namespace lifter
