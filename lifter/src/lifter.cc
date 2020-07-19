#include "lifter/lifter.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "lifter/disas.hh"
#include "mach/aarch64/aarch64-common.hh"
#include "utils/assert.hh"

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
	return r == ARM64_REG_X29 || r == ARM64_REG_X30;
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

	UNREACHABLE("Register not supported");
}

ir::tree::temp *lifter::translate_gpr(arm64_reg r)
{
	auto temp = mach::aarch64::reg_to_temp(creg_to_reg(r));
	unsigned sz = r >= ARM64_REG_W0 && r <= ARM64_REG_W30 ? 4 : 8;

	return amd_target_->make_temp(
		temp, new types::builtin_ty(types::type::INT, sz,
					    types::signedness::UNSIGNED,
					    *amd_target_));
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
					       amd_target_->integer_type());
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
				       amd_target_->integer_type());
}

ir::tree::rexp lifter::arm64_handle_ADD_reg(cs_arm64_op rn, cs_arm64_op rm)
{
	return amd_target_->make_binop(
		ops::binop::PLUS, translate_gpr(rn.reg),
		shift(translate_gpr(rm.reg), rm.shift.type, rm.shift.value),
		amd_target_->integer_type());
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

ir::tree::rstm lifter::lift(const disas_insn &insn)
{
	switch (insn.id()) {
		HANDLER(MOV);
		HANDLER(MOVZ);
		HANDLER(ADD);
	default:
		std::cerr << "Unimplemented instruction " << insn.as_str()
			  << '\n';
		UNREACHABLE("Unimplemented instruction");
	}
}

std::vector<ir::tree::rstm> lifter::lift(const uint8_t *buf, size_t sz)
{
	std::vector<ir::tree::rstm> ret;
	ir::ir_pretty_printer pir(std::cout);

	disas d(buf, sz);

	for (size_t i = 0; i < d.insn_count(); i++) {
		disas_insn ins = d[i];
		std::cout << ins.as_str() << '\n';

		auto r = lift(ins);
		r->accept(pir);
		ret.push_back(r);
	}

	return ret;
}
} // namespace lifter
