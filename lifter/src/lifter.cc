#include "lifter/lifter.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "lifter/disas.hh"
#include "mach/aarch64/aarch64-common.hh"
#include "utils/assert.hh"
#include "fmt/format.h"
#include "utils/math.hh"
#include "utils/bits.hh"

#define LIFTER_INSTRUCTION_LOG 0

#define HANDLER(Kind)                                                          \
	case ARM64_INS_##Kind:                                                 \
		return arm64_handle_##Kind(insn)

#define NOPHANDLER(Kind)                                                       \
	case ARM64_INS_##Kind:                                                 \
		return SEQ()

#define MOVE(D, S) lifter_move(D, S)
#define MEM(E) amd_target_->make_mem(E)
#define LABEL(L) amd_target_->make_label(L)
#define NAME(N) amd_target_->make_name(N)
#define CNST(C) amd_target_->make_cnst(C, types::signedness::UNSIGNED, 8)
#define CNST2(C) amd_target_->make_cnst(C, types::signedness::UNSIGNED, 2)
#define CNSTS(C, T)                                                            \
	amd_target_->make_cnst(C, types::signedness::UNSIGNED,                 \
			       (T)->assem_size())
#define CNSTZ(C, S) amd_target_->make_cnst(C, types::signedness::UNSIGNED, S);
#define TTEMP(R, T) amd_target_->make_temp(R, T)
#define RTEMP(R) amd_target_->make_temp(R, arm_target_->gpr_type())
#define GPR(R) translate_gpr(R, false, 0, types::signedness::UNSIGNED)
#define GPR8(R) translate_gpr(R, true, 8, types::signedness::UNSIGNED)
#define SGPR(R) translate_gpr(R, false, 0, types::signedness::SIGNED)
#define SGPR8(R) translate_gpr(R, true, 8, types::signedness::SIGNED)
#define ADD(L, R, T) amd_target_->make_binop(ops::binop::PLUS, L, R, T)
#define BINOP(Op, L, R, T) amd_target_->make_binop(ops::binop::Op, L, R, T)
#define UNARYOP(Op, E, T) amd_target_->make_unaryop(ops::unaryop::Op, E, T)
#define SEQ(...) amd_target_->make_seq({__VA_ARGS__})
#define CJUMP(Op, L, R, T, F) amd_target_->make_cjump(Op, L, R, T, F)
#define JUMP(L, A) amd_target_->make_jump(L, A)
#define CALL(F, A, T) amd_target_->make_call(F, A, T)
#define SEXP(E) amd_target_->make_sexp(E)
#define CX(Op, L, R) ir::tree::meta_cx(*amd_target_, Op, L, R)

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

uint64_t register_size(arm64_reg r)
{
	if ((r >= ARM64_REG_W0 && r <= ARM64_REG_W30) || r == ARM64_REG_WZR)
		return 32;
	if (r >= ARM64_REG_X0 && r <= ARM64_REG_X28)
		return 64;
	if (r == ARM64_REG_X29 || r == ARM64_REG_X30 || r == ARM64_REG_SP
	    || r == ARM64_REG_XZR)
		return 64;

	UNREACHABLE("Unknown register size");
}

ir::tree::rstm lifter::lifter_move(ir::tree::rexp d, ir::tree::rexp s)
{
	if (auto cnst = d.as<ir::tree::cnst>())
		return SEXP(s);
	return amd_target_->move_ext(d, s);
}

static bool is_offset_addressing(arm64_op_mem m)
{
	return m.base != ARM64_REG_INVALID && m.index != ARM64_REG_INVALID;
}

static bool is_base_reg_addressing(arm64_op_mem m)
{
	return m.base != ARM64_REG_INVALID && m.index == ARM64_REG_INVALID
	       && m.disp == 0;
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

	UNREACHABLE("Register {} not supported", r);
}

ir::tree::rstm lifter::set_state_field(const std::string &name,
				       ir::tree::rexp val)
{
	return MOVE(MEM(ADD(bank_->exp(), CNST(bank_type_->member_offset(name)),
			    new types::pointer_ty(amd_target_->gpr_type()))),
		    val);
}

ir::tree::rexp lifter::get_state_field(const std::string &name)
{
	return MEM(ADD(bank_->exp(), CNST(bank_type_->member_offset(name)),
		       new types::pointer_ty(amd_target_->gpr_type())));
}

ir::tree::rexp lifter::translate_gpr(arm64_reg r, bool force_size,
				     size_t forced, types::signedness sign)
{
	if (r == ARM64_REG_XZR)
		return CNST(0);
	if (r == ARM64_REG_WZR)
		return CNSTZ(0, 4);

	auto reg = creg_to_reg(r);
	unsigned sz = forced;

	if (!force_size)
		sz = register_size(r) / 8;

	return TTEMP(regs_[reg], arm_target_->integer_type(sign, sz));
}

ir::tree::rexp lifter::translate_mem_op(arm64_op_mem m, size_t sz,
					arm64_shifter st, unsigned s,
					arm64_extender ext)
{
	auto base = GPR(m.base);
	base->ty_ = new types::pointer_ty(
		arm_target_->integer_type(types::signedness::UNSIGNED, sz));

	if (m.base != ARM64_REG_INVALID && m.index != ARM64_REG_INVALID) {
		auto index = GPR(m.index);
		return ADD(base, shift_or_extend(index, st, s, ext),
			   base->ty_->clone());
	} else if (m.base != ARM64_REG_INVALID && m.disp != 0) {
		return ADD(base, CNST(m.disp), base->ty_->clone());
	} else if (m.base != ARM64_REG_INVALID && m.disp == 0) {
		return base;
	}

	UNREACHABLE("Unimplemented mem op");
}

ir::tree::rexp lifter::shift(ir::tree::rexp exp, arm64_shifter shifter,
			     unsigned value)
{
	switch (shifter) {
	case ARM64_SFT_INVALID:
		return exp;
	case ARM64_SFT_LSL:
		return BINOP(BITLSHIFT, exp, CNST(value), exp->ty()->clone());
	case ARM64_SFT_LSR:
		return BINOP(BITRSHIFT, exp, CNST(value), exp->ty()->clone());
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

	return MOVE(GPR8(dst), GPR(src));
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

	// MOVZ zeroes the register
	return MOVE(GPR8(rd.reg),
		    shift(CNST(imm.imm), imm.shift.type, imm.shift.value));
}

ir::tree::rexp lifter::arm64_handle_ADD_imm(cs_arm64_op rn, cs_arm64_op imm)
{
	ir::tree::rexp l = GPR(rn.reg);

	return ADD(
		l,
		shift(CNSTS(imm.imm, l->ty()), imm.shift.type, imm.shift.value),
		l->ty()->clone());
}

ir::tree::rexp lifter::arm64_handle_ADD_reg(cs_arm64_op rn, cs_arm64_op rm)
{
	ir::tree::rexp l = GPR(rn.reg);

	return ADD(l,
		   shift_or_extend(GPR(rm.reg), rm.shift.type, rm.shift.value,
				   rm.ext),
		   l->ty()->clone());
}

ir::tree::rstm lifter::arm64_handle_ADD(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	if (mach_det->update_flags)
		return arm64_handle_ADDS(insn);

	ASSERT(mach_det->op_count == 3, "Impossible operand count");

	cs_arm64_op rd = mach_det->operands[0];
	cs_arm64_op rn = mach_det->operands[1];
	ASSERT(rd.type == ARM64_OP_REG && rn.type == ARM64_OP_REG,
	       "Wrong operands");

	cs_arm64_op m = mach_det->operands[2];
	auto op = m.type == ARM64_OP_IMM ? arm64_handle_ADD_imm(rn, m)
					 : arm64_handle_ADD_reg(rn, m);

	return MOVE(GPR8(rd.reg), op);
}

ir::tree::rstm lifter::translate_ADDS(size_t addr, arm64_reg rd, arm64_reg rn,
				      cs_arm64_op rm)
{
	ir::tree::rexp lhs = GPR(rn);
	ir::tree::rexp rhs = shift_or_extend(GPR(rm.reg), rm.shift.type,
					     rm.shift.value, rm.ext);

	ir::tree::rexp res = BINOP(PLUS, lhs, rhs, lhs->ty()->clone());

	return SEQ(MOVE(GPR8(rd), res),
		   set_cmp_values(addr, lhs, rhs,
				  register_size(rd) == 32 ? flag_op::ADDS32
							  : flag_op::ADDS64));
}

ir::tree::rstm lifter::arm64_handle_ADDS(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto rm = mach_det->operands[2];

	return translate_ADDS(insn.address(), rd, rn, rm);
}

ir::tree::rstm lifter::arm64_handle_CMN(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	ASSERT(mach_det->op_count == 2, "Too many operands");

	auto rn = mach_det->operands[0].reg;
	auto snd = mach_det->operands[1];

	if (snd.type == ARM64_OP_REG)
		return translate_ADDS(insn.address(), ARM64_REG_XZR, rn, snd);

	return set_cmp_values(insn.address(), GPR(rn), CNST2(snd.imm),
			      register_size(rn) == 32 ? ADDS32 : ADDS64);
}


ir::tree::rexp lifter::extend(ir::tree::rexp e, arm64_extender ext)
{
	/*
	 * Zext can be used to change the size of an expression, even to a
	 * lower size.
	 */
	auto gpr_ty = arm_target_->gpr_type();

	switch (ext) {
	case ARM64_EXT_INVALID:
		return e;
	case ARM64_EXT_SXTW:
		return amd_target_->make_sext(
			amd_target_->make_zext(
				e, arm_target_->integer_type(
					   types::signedness::SIGNED, 4)),
			gpr_ty);
	case ARM64_EXT_UXTW:
		return amd_target_->make_sext(
			amd_target_->make_zext(
				e, arm_target_->integer_type(
					   types::signedness::UNSIGNED, 4)),
			gpr_ty);
	default:
		UNREACHABLE("Unimplemented extension");
	}
}

ir::tree::rexp lifter::shift_or_extend(ir::tree::rexp e, arm64_shifter shifter,
				       unsigned s, arm64_extender ext)
{
	ir::tree::rexp ret = e;

	if (ext != ARM64_EXT_INVALID)
		ret = extend(ret, ext);
	if (shifter != ARM64_SFT_INVALID)
		ret = shift(ret, shifter, s);

	return ret;
}

ir::tree::rstm lifter::arm64_handle_SUB_reg(arm64_reg rd, arm64_reg rn,
					    cs_arm64_op rm)
{
	ir::tree::rexp reg = GPR(rn);

	return MOVE(GPR8(rd), BINOP(MINUS, reg,
				    shift_or_extend(GPR(rm.reg), rm.shift.type,
						    rm.shift.value, rm.ext),
				    reg->ty()->clone()));
}

ir::tree::rstm lifter::arm64_handle_SUB_imm(arm64_reg rd, arm64_reg rn,
					    int64_t imm)
{
	ir::tree::rexp reg = GPR(rn);

	return MOVE(GPR8(rd),
		    BINOP(MINUS, reg, CNST2(imm), reg->ty()->clone()));
}

ir::tree::rstm lifter::arm64_handle_SUB(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0];
	auto rn = mach_det->operands[1];
	auto third = mach_det->operands[2];

	if (third.type == ARM64_OP_REG)
		return arm64_handle_SUB_reg(rd.reg, rn.reg, third);
	return arm64_handle_SUB_imm(rd.reg, rn.reg, third.imm);
	UNREACHABLE("Unimplemented sub");
}

ir::tree::rstm lifter::arm64_handle_NEG(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rm = mach_det->operands[1];

	return arm64_handle_SUB_reg(
		rd, register_size(rd) == 64 ? ARM64_REG_XZR : ARM64_REG_WZR,
		rm);
}

ir::tree::rstm lifter::arm64_handle_LDR_imm(cs_arm64_op xt, cs_arm64_op imm,
					    size_t sz, types::signedness sign)
{
	auto *cnst = CNST(imm.imm);
	cnst->ty_ = new types::pointer_ty(arm_target_->integer_type(sign, sz));

	return lifter_cb_.perform(MOVE(GPR8(xt.reg), MEM(cnst)));
}

ir::tree::rstm lifter::arm64_handle_LDR_reg(cs_arm64_op xt, cs_arm64_op src,
					    size_t sz, types::signedness sign)
{
	auto m = MEM(translate_mem_op(src.mem, sz, src.shift.type,
				      src.shift.value, src.ext));
	m->ty()->set_signedness(sign);

	return lifter_cb_.perform(MOVE(GPR8(xt.reg), m));
}

ir::tree::rstm lifter::arm64_handle_LDR_pre(cs_arm64_op xt, cs_arm64_op src,
					    size_t sz, types::signedness sign)
{
	auto base = translate_mem_op(src.mem, sz);

	return SEQ(arm64_handle_LDR_base_offset(xt, src, sz, sign),
		   MOVE(GPR8(src.mem.base), base));
}

ir::tree::rstm lifter::arm64_handle_LDR_base_offset(cs_arm64_op xt,
						    cs_arm64_op src, size_t sz,
						    types::signedness sign)
{
	auto t = GPR8(xt.reg);
	auto addr = translate_mem_op(src.mem, sz);
	auto m = MEM(addr);
	m->ty()->set_signedness(sign);

	return lifter_cb_.perform(MOVE(t, m));
}

ir::tree::rstm lifter::arm64_handle_LDR_post(cs_arm64_op xt, cs_arm64_op src,
					     cs_arm64_op imm, size_t sz,
					     types::signedness sign)
{
	auto t = GPR8(xt.reg);
	auto base = translate_mem_op(src.mem, sz);
	auto m = MEM(base);
	m->ty()->set_signedness(sign);

	return SEQ(lifter_cb_.perform(MOVE(t, m)),
		   MOVE(GPR8(src.mem.base),
			ADD(GPR8(src.mem.base), CNST(imm.imm), base->ty_)));
}

ir::tree::rstm lifter::arm64_handle_LDR_size(const disas_insn &insn, size_t sz,
					     types::signedness sign)
{
	const cs_arm64 *mach_det = insn.mach_detail();

	cs_arm64_op xt = mach_det->operands[0];
	cs_arm64_op base = mach_det->operands[1];

	/*
	 * ldr x0, label
	 */
	if (base.type == ARM64_OP_IMM)
		return arm64_handle_LDR_imm(xt, base, sz, sign);

	if (mach_det->op_count == 2) {
		/*
		 * ldr x0, [x1]
		 * ldr x0, [x1, x2]
		 */
		if (is_offset_addressing(base.mem)
		    || is_base_reg_addressing(base.mem))
			return arm64_handle_LDR_reg(xt, base, sz, sign);

		if (mach_det->writeback)
			return arm64_handle_LDR_pre(xt, base, sz, sign);
		else
			return arm64_handle_LDR_base_offset(xt, base, sz, sign);
	}
	if (mach_det->op_count == 3) {
		/*
		 * ldr x0, [x1], #imm
		 */
		return arm64_handle_LDR_post(xt, base, mach_det->operands[2],
					     sz, sign);
	}

	UNREACHABLE("Unimplemented LDR form");
}

ir::tree::rstm lifter::arm64_handle_LDR(const disas_insn &insn)
{
	size_t sz = register_size(insn.mach_detail()->operands[0].reg) / 8;
	return arm64_handle_LDR_size(insn, sz);
}

ir::tree::rstm lifter::arm64_handle_LDRH(const disas_insn &insn)
{
	return arm64_handle_LDR_size(insn, 2);
}

ir::tree::rstm lifter::arm64_handle_LDRB(const disas_insn &insn)
{
	return arm64_handle_LDR_size(insn, 1);
}

ir::tree::rstm lifter::arm64_handle_LDRSW(const disas_insn &insn)
{
	return arm64_handle_LDR_size(insn, 4, types::signedness::SIGNED);
}

ir::tree::rstm lifter::arm64_handle_LDAXR(const disas_insn &insn)
{
	return arm64_handle_LDR(insn);
}

ir::tree::rstm lifter::arm64_handle_MOVK(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	cs_arm64_op xd = mach_det->operands[0];
	cs_arm64_op imm = mach_det->operands[1];

	auto dest = GPR8(xd.reg);
	auto cnst = CNST(imm.imm);

	return MOVE(dest, BINOP(BITOR, dest,
				shift(cnst, imm.shift.type, imm.shift.value),
				dest->ty()->clone()));
}

ir::tree::rstm lifter::next_address(ir::tree::rexp addr)
{
	return SEQ(set_state_field("exit_reason", CNST(BB_END)),
		   MOVE(RTEMP(amd_target_->rv()), addr));
}

ir::tree::rstm lifter::arm64_handle_RET(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto xn = mach_det->op_count == 0 ? ARM64_REG_X30
					  : mach_det->operands[0].reg;

	return next_address(GPR(xn));
}

ir::tree::rstm lifter::arm64_handle_BL(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto imm = mach_det->operands[0];

	return SEQ(MOVE(GPR8(ARM64_REG_X30), CNST(insn.address() + 4)),
		   next_address(CNST(imm.imm)));
}

ir::tree::rstm lifter::arm64_handle_BLR(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto rn = mach_det->operands[0].reg;

	return SEQ(MOVE(GPR8(ARM64_REG_X30), CNST(insn.address() + 4)),
		   next_address(GPR(rn)));
}

ir::tree::rstm lifter::set_cmp_values(uint64_t address, ir::tree::rexp lhs,
				      ir::tree::rexp rhs, enum flag_op op)
{
	return SEQ(set_state_field("flag_a", lhs),
		   set_state_field("flag_b", rhs),
		   set_state_field("flag_op", CNST(op)),
		   set_state_field("exit_reason", CNST(SET_FLAGS)),
		   MOVE(RTEMP(amd_target_->rv()), CNST(address + 4)));
}

ir::tree::rstm lifter::arm64_handle_CMP_imm(uint64_t address, cs_arm64_op xn,
					    cs_arm64_op imm)
{
	return set_cmp_values(
		address, GPR(xn.reg),
		shift(CNST(imm.imm), imm.shift.type, imm.shift.value),
		register_size(xn.reg) == 32 ? flag_op::CMP32 : flag_op::CMP64);
}
ir::tree::rstm lifter::arm64_handle_CMP_reg(uint64_t address, cs_arm64_op xn,
					    cs_arm64_op xm)
{
	return set_cmp_values(address, GPR(xn.reg), GPR(xm.reg),
			      register_size(xn.reg) == 32 ? flag_op::CMP32
							  : flag_op::CMP64);
}

ir::tree::rstm lifter::arm64_handle_CMP(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto xn = mach_det->operands[0];
	auto other = mach_det->operands[1];

	if (other.type == ARM64_OP_IMM)
		return arm64_handle_CMP_imm(insn.address(), xn, other);
	if (other.type == ARM64_OP_REG)
		return arm64_handle_CMP_reg(insn.address(), xn, other);

	UNREACHABLE("Unimplemented cmp form");
}

ir::tree::rstm lifter::translate_CCMP(uint64_t address, arm64_reg rn,
				      ir::tree::rexp rhs, int64_t nzcv,
				      arm64_cc cond)
{
	/*
	 * if cond then
	 *      cmp xn, rhs
	 * else
	 *      flag_update(nzcv)
	 *
	 * cjump cond, tcond fcond
	 * tcond:
	 * set_cmp_values(xn, imm) # sets the next block address
	 * jmp end
	 * fcond:
	 * flag_update(nzcv)
	 * next_address(address + 4)
	 * end:
	 */

	utils::label tcond;
	utils::label fcond;
	utils::label end;

	auto cj = cc_jump(cond, tcond, fcond);
	auto set = set_cmp_values(address, GPR(rn), rhs,
				  register_size(rn) == 32 ? flag_op::CMP32
							  : flag_op::CMP64);
	auto update = set_state_field("nzcv", CNST(nzcv));

	return SEQ(cj, LABEL(tcond), set, JUMP(NAME(end), {end}), LABEL(fcond),
		   update, next_address(CNST(address + 4)), LABEL(end));
}

ir::tree::rstm lifter::arm64_handle_CCMP_imm(uint64_t address, arm64_reg xn,
					     cs_arm64_op imm, int64_t nzcv,
					     arm64_cc cond)
{
	return translate_CCMP(
		address, xn,
		shift(CNST(imm.imm), imm.shift.type, imm.shift.value), nzcv,
		cond);
}

ir::tree::rstm lifter::arm64_handle_CCMP(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xn = mach_det->operands[0];
	auto other = mach_det->operands[1];
	auto nzcv = mach_det->operands[2].imm;
	auto cond = mach_det->cc;

	if (other.type == ARM64_OP_IMM)
		return arm64_handle_CCMP_imm(insn.address(), xn.reg, other,
					     nzcv, cond);
	else
		return translate_CCMP(insn.address(), xn.reg, GPR(other.reg),
				      nzcv, cond);

	UNREACHABLE("Unimplemented CCMP");
}

ir::tree::rstm lifter::arm64_handle_B(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	auto lbl = mach_det->operands[0];
	ASSERT(lbl.type == ARM64_OP_IMM, "only branch to labels");

	if (mach_det->cc == ARM64_CC_INVALID || mach_det->cc == ARM64_CC_AL
	    || mach_det->cc == ARM64_CC_NV) {
		return next_address(CNST(lbl.imm));
	}

	auto fail_addr = insn.address() + 4;
	auto ok_addr = lbl.imm;

	return cc_jump(mach_det->cc, CNST(ok_addr), CNST(fail_addr));
}

ir::tree::rstm lifter::arm64_handle_BR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rn = mach_det->operands[0].reg;

	return next_address(GPR(rn));
}

ir::tree::rstm lifter::arm64_handle_STP_post(cs_arm64_op xt1, cs_arm64_op xt2,
					     cs_arm64_op xn, cs_arm64_op imm)
{
	auto r1 = GPR(xt1.reg);
	auto r2 = GPR(xt2.reg);
	auto base = GPR(xn.reg);
	utils::ref<types::ty> ptr_ty = new types::pointer_ty(r1->ty_);
	base->ty_ = ptr_ty;

	return SEQ(lifter_cb_.perform(MOVE(MEM(base), r1)),
		   lifter_cb_.perform(MOVE(
			   MEM(ADD(base, CNST(r1->ty_->assem_size()), ptr_ty)),
			   r2)),
		   MOVE(base, ADD(GPR(xn.reg), CNST(imm.imm),
				  arm_target_->gpr_type())));
}

ir::tree::rstm lifter::arm64_handle_STP_pre(cs_arm64_op xt1, cs_arm64_op xt2,
					    cs_arm64_op xn)
{
	auto dest = GPR(xn.mem.base);

	return SEQ(arm64_handle_STP_base_offset(xt1, xt2, xn),
		   MOVE(dest, ADD(dest, CNST(xn.mem.disp), dest->ty_)));
}

ir::tree::rstm lifter::arm64_handle_STP_base_offset(cs_arm64_op xt1,
						    cs_arm64_op xt2,
						    cs_arm64_op xn)
{
	auto r1 = GPR(xt1.reg);
	auto r2 = GPR(xt2.reg);
	utils::ref<types::ty> ptr_ty = new types::pointer_ty(r1->ty_);

	ir::tree::rexp base = ADD(GPR(xn.mem.base), CNST(xn.mem.disp), ptr_ty);

	return SEQ(lifter_cb_.perform(MOVE(MEM(base), r1)),
		   lifter_cb_.perform(MOVE(
			   MEM(ADD(base, CNST(r1->ty_->assem_size()), ptr_ty)),
			   r2)));
}

ir::tree::rstm lifter::arm64_handle_STP(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();
	auto xt1 = mach_det->operands[0];
	auto xt2 = mach_det->operands[1];
	auto xn = mach_det->operands[2];

	if (mach_det->op_count == 4)
		return arm64_handle_STP_post(xt1, xt2, xn,
					     mach_det->operands[3]);

	if (mach_det->writeback)
		return arm64_handle_STP_pre(xt1, xt2, xn);
	else
		return arm64_handle_STP_base_offset(xt1, xt2, xn);
}

ir::tree::rstm lifter::arm64_handle_LDP_post(cs_arm64_op xt1, cs_arm64_op xt2,
					     cs_arm64_op xn, cs_arm64_op imm)
{
	auto r1 = GPR(xt1.reg);
	auto r2 = GPR(xt2.reg);
	auto base = GPR(xn.reg);
	utils::ref<types::ty> ptr_ty = new types::pointer_ty(r1->ty_);
	base->ty_ = ptr_ty;

	return SEQ(lifter_cb_.perform(MOVE(r1, MEM(base))),
		   lifter_cb_.perform(
			   MOVE(r2, MEM(ADD(base, CNST(r1->ty_->assem_size()),
					    ptr_ty)))),
		   MOVE(base, ADD(GPR(xn.reg), CNST(imm.imm),
				  arm_target_->gpr_type())));
}

ir::tree::rstm lifter::arm64_handle_LDP_pre(cs_arm64_op xt1, cs_arm64_op xt2,
					    cs_arm64_op xn)
{
	auto dest = GPR(xn.mem.base);

	return SEQ(arm64_handle_STP_base_offset(xt1, xt2, xn),
		   MOVE(dest, ADD(dest, CNST(xn.mem.disp), dest->ty_)));
}

ir::tree::rstm lifter::arm64_handle_LDP_base_offset(cs_arm64_op xt1,
						    cs_arm64_op xt2,
						    cs_arm64_op xn)
{
	auto r1 = GPR(xt1.reg);
	auto r2 = GPR(xt2.reg);
	utils::ref<types::ty> ptr_ty = new types::pointer_ty(r1->ty_);

	ir::tree::rexp base = ADD(GPR(xn.mem.base), CNST(xn.mem.disp), ptr_ty);

	return SEQ(lifter_cb_.perform(MOVE(r1, MEM(base))),
		   lifter_cb_.perform(
			   MOVE(r2, MEM(ADD(base, CNST(r1->ty_->assem_size()),
					    ptr_ty)))));
}

ir::tree::rstm lifter::arm64_handle_LDP(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xt1 = mach_det->operands[0];
	auto xt2 = mach_det->operands[1];
	auto xn = mach_det->operands[2];

	if (mach_det->op_count == 4)
		return arm64_handle_LDP_post(xt1, xt2, xn,
					     mach_det->operands[3]);
	if (mach_det->writeback)
		return arm64_handle_LDP_pre(xt1, xt2, xn);
	else
		return arm64_handle_LDP_base_offset(xt1, xt2, xn);

	UNREACHABLE("Unhandled LDP");
}

ir::tree::rstm lifter::arm64_handle_ADRP(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xd = mach_det->operands[0];
	auto imm = mach_det->operands[1];

	return MOVE(GPR8(xd.reg), CNST(imm.imm));
}

ir::tree::rstm lifter::arm64_handle_STXR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xs = mach_det->operands[0].reg;
	auto xt = mach_det->operands[1].reg;
	auto xn = mach_det->operands[2];

	auto t = GPR(xt);

	/*
	 * unicorn performs a read of the address before storing to it for
	 * some reason, so do the same here to avoid breaking the harness.
	 */
	utils::temp unused_temp;

	utils::temp addr;
	auto addr_move =
		MOVE(TTEMP(addr, new types::pointer_ty(t->ty()->clone())),
		     translate_mem_op(xn.mem, 4));

	auto useless_move =
		MOVE(TTEMP(unused_temp, t->ty()->clone()),
		     MEM(TTEMP(addr, new types::pointer_ty(t->ty()->clone()))));

	return SEQ(addr_move, lifter_cb_.perform(useless_move),
		   lifter_cb_.perform(MOVE(
			   MEM(TTEMP(addr,
				     new types::pointer_ty(t->ty()->clone()))),
			   t)),
		   MOVE(GPR8(xs), CNST(0)));
}

ir::tree::rstm lifter::arm64_handle_STLXR(const disas_insn &insn)
{
	return arm64_handle_STXR(insn);
}

ir::tree::rstm lifter::arm64_handle_LDXR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto sz = register_size(mach_det->operands[0].reg) / 8;
	return arm64_handle_LDR_size(insn, sz);
}

ir::tree::rstm lifter::arm64_handle_STR_reg(cs_arm64_op xt, cs_arm64_op dst,
					    size_t sz)
{
	return lifter_cb_.perform(
		MOVE(MEM(translate_mem_op(dst.mem, sz)), GPR(xt.reg)));
}


ir::tree::rstm lifter::arm64_handle_STR_pre(cs_arm64_op xt, cs_arm64_op dst,
					    size_t sz)
{
	auto base = translate_mem_op(dst.mem, sz);

	return SEQ(arm64_handle_STR_base_offset(xt, dst, sz),
		   MOVE(GPR8(dst.mem.base), base));
}

ir::tree::rstm lifter::arm64_handle_STR_base_offset(cs_arm64_op xt,
						    cs_arm64_op dst, size_t sz)
{
	auto t = GPR(xt.reg);

	auto addr = translate_mem_op(dst.mem, sz);

	return lifter_cb_.perform(MOVE(MEM(addr), t));
}

ir::tree::rstm lifter::arm64_handle_STR_post(cs_arm64_op xt, cs_arm64_op dst,
					     cs_arm64_op imm, size_t sz)
{
	auto t = GPR(xt.reg);
	auto base = translate_mem_op(dst.mem, sz);

	return SEQ(lifter_cb_.perform(MOVE(MEM(base), t)),
		   MOVE(GPR8(dst.mem.base),
			ADD(GPR8(dst.mem.base), CNST(imm.imm), base->ty_)));
}

ir::tree::rstm lifter::arm64_handle_STRB(const disas_insn &insn)
{
	return arm64_handle_STR_size(insn, 1);
}

ir::tree::rstm lifter::arm64_handle_STRH(const disas_insn &insn)
{
	return arm64_handle_STR_size(insn, 2);
}

ir::tree::rstm lifter::arm64_handle_STR(const disas_insn &insn)
{
	/* wd or xd */
	size_t sz = register_size(insn.mach_detail()->operands[0].reg) / 8;
	return arm64_handle_STR_size(insn, sz);
}

ir::tree::rstm lifter::arm64_handle_STUR(const disas_insn &insn)
{
	size_t sz = register_size(insn.mach_detail()->operands[0].reg) / 8;
	return arm64_handle_STR_size(insn, sz);
}

ir::tree::rstm lifter::arm64_handle_STURB(const disas_insn &insn)
{
	return arm64_handle_STR_size(insn, 1);
}

ir::tree::rstm lifter::arm64_handle_STR_size(const disas_insn &insn, size_t sz)
{
	auto *mach_det = insn.mach_detail();

	auto xt = mach_det->operands[0];
	auto dst = mach_det->operands[1];

	if (mach_det->op_count == 2) {
		/*
		 * str x0, [x1]
		 * str x0, [x1, x2]
		 */
		if (is_offset_addressing(dst.mem)
		    || is_base_reg_addressing(dst.mem))
			return arm64_handle_STR_reg(xt, dst, sz);
		/*
		 * str x0, [x1, #imm]!
		 * str x0, [x1, #imm]
		 */
		if (mach_det->writeback)
			return arm64_handle_STR_pre(xt, dst, sz);
		else
			return arm64_handle_STR_base_offset(xt, dst, sz);
	}
	if (mach_det->op_count == 3) {
		/*
		 * str x0, [x1], #imm
		 */
		return arm64_handle_STR_post(xt, dst, mach_det->operands[2],
					     sz);
	}

	UNREACHABLE("Unimplemted");
}

ir::tree::meta_cx lifter::translate_cc(arm64_cc cond)
{
	// XXX: Rewrite this using shared/functions/system/ConditionHolds from
	// the manual

	auto nzcv = get_state_field("nzcv");

	if (cond == ARM64_CC_EQ) {
		return CX(ops::cmpop::EQ,
			  BINOP(BITAND, nzcv, CNST(Z), amd_target_->gpr_type()),
			  CNST(Z));
	}
	if (cond == ARM64_CC_NE) {
		return CX(ops::cmpop::NEQ,
			  BINOP(BITAND, nzcv, CNST(Z), amd_target_->gpr_type()),
			  CNST(Z));
	}
	if (cond == ARM64_CC_HS) {
		return CX(ops::cmpop::EQ,
			  BINOP(BITAND, nzcv, CNST(C), amd_target_->gpr_type()),
			  CNST(C));
	}
	if (cond == ARM64_CC_HI) {
		return CX(ops::cmpop::EQ,
			  BINOP(BITAND, nzcv, CNST(C | Z),
				amd_target_->gpr_type()),
			  CNST(C));
	}
	if (cond == ARM64_CC_LO) {
		return CX(ops::cmpop::EQ,
			  BINOP(BITAND, nzcv, CNST(C), amd_target_->gpr_type()),
			  CNST(0));
	}
	if (cond == ARM64_CC_LS) {
		auto ret = translate_cc(ARM64_CC_HI);
		return CX(ops::cmpop::EQ, ret.un_ex(), CNST(0));
	}
	if (cond == ARM64_CC_GT) {
		auto nbit = BINOP(
			BITRSHIFT,
			BINOP(BITAND, nzcv, CNST(N), amd_target_->gpr_type()),
			CNST(3), amd_target_->gpr_type());
		auto vbit =
			BINOP(BITAND, nzcv, CNST(V), amd_target_->gpr_type());
		auto nveq = CX(ops::cmpop::EQ, nbit, vbit);

		auto zcheck = CX(
			ops::cmpop::EQ,
			BINOP(BITAND, nzcv, CNST(Z), amd_target_->gpr_type()),
			CNST(0));

		return CX(ops::cmpop::EQ,
			  BINOP(AND, nveq.un_ex(), zcheck.un_ex(),
				amd_target_->gpr_type()),
			  CNST(1));
	}
	if (cond == ARM64_CC_LE) {
		auto ret = translate_cc(ARM64_CC_GT);
		return CX(ops::cmpop::EQ, ret.un_ex(), CNST(0));
	}

	UNREACHABLE("Unimplemented translate_cc");
}

ir::tree::rstm lifter::cc_jump(arm64_cc cc, ir::tree::rexp true_addr,
			       ir::tree::rexp false_addr)
{
	/*
	 * cjump RHS OP LHS, ok, fail
	 * ok:
	 * next_address(true_addr)
	 * jump end
	 * fail:
	 * next_address(false_addr)
	 * end:
	 */

	return conditional_jump(translate_cc(cc), true_addr, false_addr);
}
ir::tree::rstm lifter::cc_jump(arm64_cc cc, utils::label true_label,
			       utils::label false_label)
{
	/*
	 * cjump (ncvz & cc) == cc, ok, fail
	 * ok:
	 * jump true_label
	 * fail:
	 * jump false_label
	 * end:
	 */

	return translate_cc(cc).un_cx(true_label, false_label);
}

ir::tree::rstm lifter::conditional_jump(ir::tree::meta_cx cx,
					ir::tree::rexp true_addr,
					ir::tree::rexp false_addr)
{
	auto fail_label = make_unique("fail");
	auto ok_label = make_unique("ok");
	auto end_label = make_unique("end");

	auto cj = cx.un_cx(ok_label, fail_label);

	return SEQ(cj, LABEL(ok_label), next_address(true_addr),
		   JUMP(NAME(end_label), {end_label}), LABEL(fail_label),
		   next_address(false_addr), LABEL(end_label));
}

ir::tree::rstm lifter::arm64_handle_CBZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xt = mach_det->operands[0];
	auto label = mach_det->operands[1];

	auto fail_addr = insn.address() + 4;

	return conditional_jump(CX(ops::cmpop::EQ, GPR(xt.reg), CNST(0)),
				CNST(label.imm), CNST(fail_addr));
}

ir::tree::rstm lifter::arm64_handle_CBNZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xt = mach_det->operands[0];
	auto label = mach_det->operands[1];

	auto fail_addr = insn.address() + 4;

	return conditional_jump(CX(ops::cmpop::NEQ, GPR(xt.reg), CNST(0)),
				CNST(label.imm), CNST(fail_addr));
}

ir::tree::rstm lifter::arm64_handle_NOP(const disas_insn &) { return SEQ(); }

ir::tree::rstm lifter::arm64_handle_SVC(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto imm = mach_det->operands[0];
	ASSERT(imm.imm == 0, "Not a syscall");

	return SEQ({
		set_state_field("exit_reason", CNST(SYSCALL)),
		MOVE(RTEMP(amd_target_->rv()), CNST(insn.address() + 4)),
	});
}

ir::tree::rstm lifter::translate_CSINC(arm64_reg xd, arm64_reg xn, arm64_reg xm,
				       arm64_cc cc)
{
	/*
	 * cjump LHS OP RHS, t, f
	 * t:
	 * rd = rn
	 * jump end
	 * f:
	 * rd = rm + 1
	 * end:
	 */

	utils::label t, f, end;

	auto cj = translate_cc(cc).un_cx(t, f);

	ir::tree::rexp m = GPR(xm);

	return SEQ(cj, LABEL(t), MOVE(GPR8(xd), GPR(xn)),
		   JUMP(NAME(end), {end}), LABEL(f),
		   MOVE(GPR8(xd),
			BINOP(PLUS, m, CNSTS(1, m->ty()), m->ty()->clone())),
		   LABEL(end));
}

ir::tree::rstm lifter::translate_UBFM(arm64_reg rd, arm64_reg rn, int immr,
				      int imms)
{
	/*
	 * If <imms> is greater than or equal to <immr> , this copies a
	 * bitfield of ( <imms> - <immr> +1) bits starting from bit position
	 * <immr> in the source register to the least significant bits of the
	 * destination register.
	 */
	if (imms >= immr) {
		uint64_t mask = utils::mask_range(immr, imms);

		auto bits = BINOP(BITAND, GPR(rn), CNST(mask),
				  arm_target_->gpr_type());
		auto shifted = BINOP(BITRSHIFT, bits, CNST(immr),
				     arm_target_->gpr_type());
		return MOVE(GPR8(rd), shifted);
	}

	/*
	 * If <imms> is less than <immr> , this copies a bitfield of
	 * (<imms> + 1) bits from the least significant bits of the source
	 * register to bit position (regsize - <immr>) of the destination
	 * register, where regsize is the destination register size of 32
	 * or 64 bits.
	 */

	auto regsize = register_size(rd);

	uint64_t mask = utils::mask_range(0, imms);
	auto bits = BINOP(BITAND, GPR(rn), CNST(mask), arm_target_->gpr_type());
	auto shifted = BINOP(BITLSHIFT, bits, CNST(regsize - immr),
			     arm_target_->gpr_type());

	return MOVE(GPR8(rd), shifted);
}

ir::tree::rstm lifter::arm64_handle_UBFIZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	return translate_UBFM(
		mach_det->operands[0].reg, mach_det->operands[1].reg,
		utils::math::mod(-mach_det->operands[2].imm,
				 register_size(mach_det->operands[0].reg)),
		mach_det->operands[3].imm - 1);
}

ir::tree::rstm lifter::arm64_handle_UBFX(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	return translate_UBFM(
		mach_det->operands[0].reg, mach_det->operands[1].reg,
		mach_det->operands[2].imm,
		mach_det->operands[2].imm + mach_det->operands[3].imm - 1);
}

ir::tree::rstm lifter::arm64_handle_LSR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto third = mach_det->operands[2];

	if (third.type == ARM64_OP_IMM)
		return translate_UBFM(rd, rn, third.imm, register_size(rd) - 1);
	else
		UNREACHABLE("Unimplemented LSR register");
}

ir::tree::rstm lifter::arm64_handle_LSL(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto third = mach_det->operands[2];

	auto regsize = register_size(rd);

	if (third.type == ARM64_OP_IMM)
		return translate_UBFM(rd, rn,
				      utils::math::mod(-third.imm, regsize),
				      regsize - 1 - third.imm);
	else {
		ir::tree::rexp n = GPR(rn);
		return MOVE(GPR8(rd), BINOP(BITLSHIFT, n, GPR(third.reg),
					    n->ty()->clone()));
	}
}

arm64_cc lifter::invert_cc(arm64_cc cc)
{
	switch (cc) {
	case ARM64_CC_EQ:
		return ARM64_CC_NE;
	case ARM64_CC_NE:
		return ARM64_CC_EQ;
	case ARM64_CC_HS:
		return ARM64_CC_LO;
	case ARM64_CC_HI:
		return ARM64_CC_LS;
	default:
		UNREACHABLE("Unimplemented invert_cc");
	}
}

ir::tree::rstm lifter::arm64_handle_CSET(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	return translate_CSINC(mach_det->operands[0].reg, ARM64_REG_XZR,
			       ARM64_REG_XZR, invert_cc(mach_det->cc));
}

ir::tree::rstm lifter::arm64_handle_CSINC(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto rm = mach_det->operands[2].reg;
	auto cc = mach_det->cc;

	return translate_CSINC(rd, rn, rm, cc);
}

ir::tree::rstm lifter::arm64_handle_CSEL(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto rm = mach_det->operands[2].reg;
	auto cc = mach_det->cc;

	/*
	 * cjump LHS OP RHS, t, f
	 * t:
	 * rd = rn
	 * jump end
	 * f:
	 * rd = rm
	 * end:
	 */

	utils::label t, f, end;

	auto cj = translate_cc(cc).un_cx(t, f);

	return SEQ(cj, LABEL(t), MOVE(GPR8(rd), GPR(rn)),
		   JUMP(NAME(end), {end}), LABEL(f), MOVE(GPR8(rd), GPR(rm)),
		   LABEL(end));
}

ir::tree::rstm lifter::translate_ANDS(arm64_reg rd, arm64_reg rn,
				      cs_arm64_op reg_or_imm, size_t addr)
{
	ir::tree::rexp n = GPR(rn);

	ir::tree::rexp third = reg_or_imm.type == ARM64_OP_IMM
				       ? CNSTS(reg_or_imm.imm, n->ty())
				       : GPR(reg_or_imm.reg);

	ir::tree::rexp bits = BINOP(BITAND, n, third, n->ty()->clone());

	return SEQ(MOVE(GPR8(rd), bits),
		   set_cmp_values(addr, GPR(rn), bits,
				  register_size(rd) == 32 ? ANDS32 : ANDS64));
}

ir::tree::rstm lifter::arm64_handle_ANDS(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto reg_or_imm = mach_det->operands[2];

	return translate_ANDS(rd, rn, reg_or_imm, insn.address());
}

ir::tree::rstm lifter::arm64_handle_AND(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	if (mach_det->update_flags)
		return arm64_handle_ANDS(insn);

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto reg_or_imm = mach_det->operands[2];

	ir::tree::rexp n = GPR(rn);
	ir::tree::rexp third = reg_or_imm.type == ARM64_OP_IMM
				       ? CNSTS(reg_or_imm.imm, n->ty())
				       : shift_or_extend(GPR(reg_or_imm.reg),
							 reg_or_imm.shift.type,
							 reg_or_imm.shift.value,
							 reg_or_imm.ext);

	ir::tree::rexp bits = BINOP(BITAND, n, third, n->ty()->clone());

	return MOVE(GPR8(rd), bits);
}

ir::tree::rstm lifter::arm64_handle_TBZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rt = mach_det->operands[0].reg;
	auto bit = mach_det->operands[1].imm;
	auto dest = mach_det->operands[2].imm;

	auto fail_addr = insn.address() + 4;

	return conditional_jump(CX(ops::cmpop::EQ,
				   BINOP(BITAND, GPR(rt), CNST(1ull << bit),
					 arm_target_->gpr_type()),
				   CNST(0)),
				CNST(dest), CNST(fail_addr));
}

ir::tree::rstm lifter::arm64_handle_TBNZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rt = mach_det->operands[0].reg;
	auto bit = mach_det->operands[1].imm;
	auto dest = mach_det->operands[2].imm;

	auto fail_addr = insn.address() + 4;

	return conditional_jump(CX(ops::cmpop::NEQ,
				   BINOP(BITAND, GPR(rt), CNST(1ull << bit),
					 arm_target_->gpr_type()),
				   CNST(0)),
				CNST(dest), CNST(fail_addr));
}

ir::tree::rstm lifter::arm64_handle_MRS(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rt = mach_det->operands[0].reg;
	ir::tree::rexp lhs;

	uint64_t reg = mach_det->operands[1].reg;

	if (reg == ARM64_SYSREG_DCZID_EL0)
		return MOVE(GPR8(rt), CNST(0x4)); // Same value as Unicorn
	if (reg == ARM64_SYSREG_MIDR_EL1)
		return MOVE(GPR8(rt), CNST(0x411fd070)); // Same as Unicorn
	else if (reg == 0xde82) // tpidr_el0 missing from capstone
		return MOVE(GPR8(rt), get_state_field("tpidr_el0"));
	else
		UNREACHABLE("unimplemented\n");
}

ir::tree::rstm lifter::arm64_handle_MSR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rt = mach_det->operands[1].reg;
	uint64_t reg = mach_det->operands[0].reg;

	if (reg == 0xde82)
		return set_state_field("tpidr_el0", GPR(rt));
	else
		UNREACHABLE("Unimplemented MSR");
}

ir::tree::rstm lifter::arm64_handle_TST(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rn = mach_det->operands[0].reg;
	auto reg_or_imm = mach_det->operands[1];

	if (register_size(rn) == 64)
		return translate_ANDS(ARM64_REG_XZR, rn, reg_or_imm,
				      insn.address());
	else
		return translate_ANDS(ARM64_REG_WZR, rn, reg_or_imm,
				      insn.address());
}

ir::tree::rstm lifter::arm64_handle_MOVN(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto imm = mach_det->operands[1].imm;

	uint64_t val = ~imm;
	if (register_size(rd) == 32)
		val = utils::extract_bits(val, 31, 0);

	return MOVE(GPR8(rd), CNST(val));
}

ir::tree::rstm lifter::arm64_handle_EOR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto third = mach_det->operands[2];

	ir::tree::rexp n = GPR(rn);

	if (third.type == ARM64_OP_IMM)
		return MOVE(GPR8(rd), BINOP(BITXOR, n, CNST(third.imm),
					    n->ty()->clone()));
	else
		return MOVE(
			GPR8(rd),
			BINOP(BITXOR, n,
			      shift_or_extend(GPR(third.reg), third.shift.type,
					      third.shift.value, third.ext),
			      n->ty()->clone()));
}

ir::tree::rstm lifter::arm64_handle_ORR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto third = mach_det->operands[2];

	ir::tree::rexp n = GPR(rn);

	if (third.type == ARM64_OP_IMM)
		return MOVE(GPR8(rd), BINOP(BITOR, n, CNSTS(third.imm, n->ty()),
					    n->ty()->clone()));
	else
		return MOVE(
			GPR8(rd),
			BINOP(BITOR, n,
			      shift_or_extend(GPR(third.reg), third.shift.type,
					      third.shift.value, third.ext),
			      n->ty()->clone()));
}

ir::tree::rstm lifter::arm64_handle_UDIV(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto rm = mach_det->operands[2].reg;

	return MOVE(GPR8(rd), BINOP(DIV, GPR(rn), GPR(rm),
				    arm_target_->integer_type(
					    types::signedness::UNSIGNED, 8)));
}

ir::tree::rstm lifter::translate_MADD(arm64_reg rd, arm64_reg rn, arm64_reg rm,
				      arm64_reg ra)
{
	auto n = GPR(rn);

	return MOVE(GPR8(rd),
		    BINOP(PLUS, BINOP(MULT, n, GPR(rm), n->ty()->clone()),
			  GPR(ra), n->ty()->clone()));
}

ir::tree::rstm lifter::arm64_handle_MUL(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto rm = mach_det->operands[2].reg;

	return translate_MADD(rd, rn, rm,
			      register_size(rd) == 64 ? ARM64_REG_XZR
						      : ARM64_REG_WZR);
}

ir::tree::rstm lifter::arm64_handle_MADD(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto rm = mach_det->operands[2].reg;
	auto ra = mach_det->operands[3].reg;

	return translate_MADD(rd, rn, rm, ra);
}

ir::tree::rstm lifter::arm64_handle_SXTW(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;

	return MOVE(SGPR8(rd), SGPR(rn));
}

ir::tree::rstm lifter::arm64_handle_BIC(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;
	auto rm = mach_det->operands[2];

	utils::temp val, op2;
	auto operand2 = UNARYOP(BITNOT,
				shift_or_extend(GPR(rm.reg), rm.shift.type,
						rm.shift.value, rm.ext),
				arm_target_->gpr_type());

	auto result =
		BINOP(BITAND, GPR(rn), RTEMP(op2), arm_target_->gpr_type());

	auto common = SEQ(MOVE(RTEMP(op2), operand2), MOVE(RTEMP(val), result),
			  MOVE(GPR8(rd), RTEMP(val)));
	if (!mach_det->update_flags)
		return common;

	return SEQ(common,
		   set_cmp_values(insn.address(), RTEMP(val), RTEMP(op2),
				  register_size(rd) == 32 ? ANDS32 : ANDS64));
}

ir::tree::rstm lifter::arm64_handle_REV(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;

	ir::tree::rexp src = GPR(rn);
	return MOVE(GPR8(rd), UNARYOP(REV, src, src->ty_->clone()));
}

ir::tree::rstm lifter::arm64_handle_CLZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto rd = mach_det->operands[0].reg;
	auto rn = mach_det->operands[1].reg;

	ir::tree::rexp src = GPR(rn);
	return MOVE(GPR8(rd), UNARYOP(CLZ, src, src->ty_->clone()));
}

ir::tree::rstm lifter::lift(const disas_insn &insn)
{
	switch (insn.id()) {
		HANDLER(ADD);
		HANDLER(ADRP);
		HANDLER(AND);
		HANDLER(B);
		HANDLER(BIC);
		HANDLER(BL);
		HANDLER(BLR);
		HANDLER(BR);
		HANDLER(CBNZ);
		HANDLER(CBZ);
		HANDLER(CCMP);
		HANDLER(CMN);
		HANDLER(CMP);
		HANDLER(CSINC);
		HANDLER(CSEL);
		HANDLER(CSET);
		HANDLER(CLZ);
		HANDLER(LDAXR);
		HANDLER(LDP);
		HANDLER(LDR);
		HANDLER(LDRB);
		HANDLER(LDRH);
		HANDLER(LDRSW);
		HANDLER(LSL);
		HANDLER(LSR);
		HANDLER(MADD);
		HANDLER(MOV);
		HANDLER(MOVK);
		HANDLER(MOVN);
		HANDLER(MOVZ);
		HANDLER(MRS);
		HANDLER(MSR);
		HANDLER(MUL);
		HANDLER(NEG);
		HANDLER(NOP);
		HANDLER(ORR);
		HANDLER(EOR);
		HANDLER(RET);
		HANDLER(REV);
		HANDLER(STP);
		HANDLER(STR);
		HANDLER(STUR);
		HANDLER(STURB);
		HANDLER(STRB);
		HANDLER(STRH);
		HANDLER(STXR);
		HANDLER(STLXR);
		HANDLER(LDXR);
		HANDLER(SUB);
		HANDLER(SVC);
		HANDLER(SXTW);
		HANDLER(TBNZ);
		HANDLER(TBZ);
		HANDLER(TST);
		HANDLER(UBFIZ);
		HANDLER(UBFX);
		HANDLER(UDIV);
		NOPHANDLER(PRFM);
		NOPHANDLER(HINT);
	default:
		UNREACHABLE("Unimplemented instruction {} ({})", insn.as_str(),
			    insn.insn_name());
	}
}

mach::fun_fragment lifter::lift(const disas_bb &bb)
{
	std::vector<ir::tree::rstm> ret;
	ir::ir_pretty_printer pir(std::cout);

	auto frame = amd_target_->make_frame(
		fmt::format("bb_{x}", bb.address()), {false},
		{new types::pointer_ty(bank_type_)}, true);
	frame->leaf_ = false;

	bank_ = frame->formals()[0];

	utils::uset<mach::aarch64::regs> used_regs;
	for (uint16_t creg : bb.regs())
		used_regs += creg_to_reg((arm64_reg)creg);

	for (auto reg : used_regs) {
		ret.push_back(MOVE(
			RTEMP(regs_[reg]),
			MEM(ADD(bank_->exp(), CNST(8 * reg),
				new types::pointer_ty(arm_target_->integer_type(
					types::signedness::UNSIGNED, 8))))));
	}

	const auto &insns = bb.insns();
	for (size_t i = 0; i < insns.size(); i++) {
		disas_insn ins = insns[i];

#if LIFTER_INSTRUCTION_LOG
		fmt::print("Lifting instruction {} ({}/{})\n", ins.as_str(),
			   i + 1, insns.size());
#endif

		auto r = lift(ins);

#if LIFTER_INSTRUCTION_LOG
		r->accept(pir);
#endif

		ret.push_back(amd_target_->make_asm_block({"nop"}, {}, {}, {}));
		ret.push_back(amd_target_->make_asm_block(
			{fmt::format("# {}", ins.as_str())}, {}, {}, {}));
		ret.push_back(r);
	}

	/*
	 * In single step mode, basic blocks are not necessarily complete, and
	 * the exit reason and return value are not necessarily set.
	 * We set them ourselves to point to the next instruction.
	 */
	if (!bb.complete()) {
		ASSERT(bb.size() == 1,
		       "Singlestep mode, but more than one instruction");
		ret.push_back(next_address(CNST(bb.insns()[0].address() + 4)));
	}

	for (auto reg : used_regs)
		ret.push_back(MOVE(
			MEM(ADD(bank_->exp(), CNST(8 * reg),
				new types::pointer_ty(arm_target_->integer_type(
					types::signedness::UNSIGNED, 8)))),
			RTEMP(regs_[reg])));

	auto body = amd_target_->make_seq(ret);
#if LIFTER_INSTRUCTION_LOG
	body->accept(pir);
#endif

	auto ret_lbl = make_unique("ret");
	return mach::fun_fragment(frame->prepare_temps(body, ret_lbl), frame,
				  ret_lbl, make_unique("epi"));
}

static void write_cb(void *data, uint64_t addr, uint64_t size, uint64_t val)
{
	lifter *l = static_cast<lifter *>(data);

	l->dispatch_mem_write_callback(addr, size, val);
}

static void read_cb(void *data, uint64_t addr, uint64_t size)
{
	lifter *l = static_cast<lifter *>(data);

	l->dispatch_mem_read_callback(addr, size);
}

void lifter::dispatch_mem_write_callback(uint64_t addr, uint64_t size,
					 uint64_t val)
{
	for (const auto &[f, d] : mem_write_cbs_)
		f(addr, size, val, d);
}

void lifter::dispatch_mem_read_callback(uint64_t addr, uint64_t size)
{
	for (const auto &[f, d] : mem_read_cbs_)
		f(addr, size, d);
}

void lifter::add_mem_write_callback(mem_write_callback cb, void *user_data)
{
	mem_write_cbs_.emplace_back(cb, user_data);
}

void lifter::add_mem_read_callback(mem_read_callback cb, void *user_data)
{
	mem_read_cbs_.emplace_back(cb, user_data);
}

lifter::lifter()
    : amd_target_(new mach::amd64::amd64_target()),
      arm_target_(new mach::aarch64::aarch64_target()),
      lifter_cb_(*amd_target_, nullptr, nullptr, this)
{
	std::vector<symbol> names;
	std::vector<utils::ref<types::ty>> types;

	for (size_t i = 0; i < 32; i++) {
		names.push_back(fmt::format("r{}", i));
		types.push_back(arm_target_->gpr_type());
	}

	update_flags_ty_ = new types::fun_ty(amd_target_->void_type(),
					     {amd_target_->gpr_type()}, false),

	bank_type_ = new types::struct_ty(
		"state",
		{
			"regs",
			"nzcv",
			"flag_a",
			"flag_b",
			"flag_op",
			"exit_reason",
			"tpidr_el0",
		},
		{
			new types::array_ty(amd_target_->gpr_type(), 32),
			amd_target_->gpr_type(), // nzcv
			amd_target_->gpr_type(), // flag_a
			amd_target_->gpr_type(), // flag_b
			amd_target_->gpr_type(), // flag_op
			amd_target_->gpr_type(), // exit_reason
			amd_target_->gpr_type(), // tpidr_el0
		});

	// fun basic_block(state* bank) int<8>
	bb_type_ =
		new types::fun_ty(amd_target_->gpr_type(),
				  {new types::pointer_ty(bank_type_)}, false);

	auto c = amd_target_->make_cnst((uint64_t)write_cb);
	c->ty_ = new types::fun_ty(amd_target_->void_type(),
				   {
					   amd_target_->gpr_type(),
					   amd_target_->gpr_type(),
					   amd_target_->gpr_type(),
					   amd_target_->gpr_type(),
				   },
				   false);

	auto c2 = amd_target_->make_cnst((uint64_t)read_cb);
	c2->ty_ = new types::fun_ty(amd_target_->void_type(),
				    {
					    amd_target_->gpr_type(),
					    amd_target_->gpr_type(),
					    amd_target_->gpr_type(),
				    },
				    false);

	lifter_cb_.set_write_callback(c);
	lifter_cb_.set_read_callback(c2);
}
} // namespace lifter
