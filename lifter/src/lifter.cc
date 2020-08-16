#include "lifter/lifter.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "lifter/disas.hh"
#include "mach/aarch64/aarch64-common.hh"
#include "utils/assert.hh"
#include "fmt/format.h"

#define HANDLER(Kind)                                                          \
	case ARM64_INS_##Kind:                                                 \
		return arm64_handle_##Kind(insn)

#define MOVE(D, S) amd_target_->move_ext(D, S)
#define MEM(E) amd_target_->make_mem(E)
#define LABEL(L) amd_target_->make_label(L)
#define NAME(N) amd_target_->make_name(N)
#define CNST(C) amd_target_->make_cnst(C)
#define TTEMP(R, T) amd_target_->make_temp(R, T)
#define RTEMP(R) amd_target_->make_temp(R, amd_target_->gpr_type())
#define GPR(R) translate_gpr(R)
#define ADD(L, R, T) amd_target_->make_binop(ops::binop::PLUS, L, R, T)
#define BINOP(Op, L, R, T) amd_target_->make_binop(ops::binop::Op, L, R, T)
#define SEQ(...) amd_target_->make_seq({__VA_ARGS__})
#define CJUMP(Op, L, R, T, F) amd_target_->make_cjump(Op, L, R, T, F)
#define JUMP(L, A) amd_target_->make_jump(L, A)
#define CALL(F, A, T) amd_target_->make_call(F, A, T)
#define SEXP(E) amd_target_->make_sexp(E)

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

	UNREACHABLE("Register not supported");
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

ir::tree::rexp lifter::translate_gpr(arm64_reg r)
{
	if (r == ARM64_REG_XZR || r == ARM64_REG_WZR)
		return CNST(0);

	auto reg = creg_to_reg(r);
	unsigned sz = r >= ARM64_REG_W0 && r <= ARM64_REG_W30 ? 4 : 8;

	return MEM(ADD(bank_->exp(), CNST(8 * reg),
		       new types::pointer_ty(new types::builtin_ty(
			       types::type::INT, sz,
			       types::signedness::UNSIGNED, *arm_target_))));
}

ir::tree::rexp lifter::translate_mem_op(arm64_op_mem m)
{
	fmt::print("{} {} {}\n", m.base, m.index, m.disp);

	if (m.base != ARM64_REG_INVALID && m.index != ARM64_REG_INVALID) {
		auto base = GPR(m.base);
		auto index = GPR(m.index);

		return ADD(base, index, new types::pointer_ty(base->ty_));
	} else if (m.base != ARM64_REG_INVALID && m.disp != 0) {
		auto base = GPR(m.base);
		return ADD(base, CNST(m.disp),
			   new types::pointer_ty(base->ty_));
	} else if (m.base != ARM64_REG_INVALID && m.disp == 0) {
		auto base = GPR(m.base);
		base->ty_ = new types::pointer_ty(base->ty_);
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
		return BINOP(BITLSHIFT, exp, CNST(value),
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

	return MOVE(GPR(dst), GPR(src));
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

	return MOVE(GPR(rd.reg),
		    shift(CNST(imm.imm), imm.shift.type, imm.shift.value));
}

ir::tree::rexp lifter::arm64_handle_ADD_imm(cs_arm64_op rn, cs_arm64_op imm)
{
	return ADD(GPR(rn.reg),
		   shift(CNST(imm.imm), imm.shift.type, imm.shift.value),
		   amd_target_->gpr_type());
}

ir::tree::rexp lifter::arm64_handle_ADD_reg(cs_arm64_op rn, cs_arm64_op rm)
{
	return ADD(GPR(rn.reg),
		   shift(GPR(rm.reg), rm.shift.type, rm.shift.value),
		   arm_target_->gpr_type());
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

	return MOVE(GPR(rd.reg), op);
}

ir::tree::rstm lifter::arm64_handle_LDR_imm(cs_arm64_op xt, cs_arm64_op imm)
{
	return MOVE(GPR(xt.reg), CNST(imm.imm));
}

ir::tree::rstm lifter::arm64_handle_LDR_reg(cs_arm64_op xt, cs_arm64_op src,
					    size_t sz)
{
	auto m = MEM(translate_mem_op(src.mem));
	m->ty_ = new types::pointer_ty(new types::builtin_ty(
		types::type::INT, sz, types::signedness::UNSIGNED,
		*amd_target_));

	return MOVE(GPR(xt.reg), m);
}

ir::tree::rstm lifter::arm64_handle_LDR_pre(cs_arm64_op xt, cs_arm64_op src,
					    size_t sz)
{
	auto base = GPR(src.mem.base);

	return SEQ(arm64_handle_LDR_base_offset(xt, src, sz),
		   MOVE(base, ADD(base, CNST(src.mem.disp), base->ty_)));
}

ir::tree::rstm lifter::arm64_handle_LDR_base_offset(cs_arm64_op xt,
						    cs_arm64_op src, size_t sz)
{
	auto t = GPR(xt.reg);

	auto addr = translate_mem_op(src.mem);
	addr->ty_ = new types::pointer_ty(new types::builtin_ty(
		types::type::INT, sz, types::signedness::UNSIGNED,
		*amd_target_));

	return MOVE(t, MEM(addr));
}

ir::tree::rstm lifter::arm64_handle_LDR_post(cs_arm64_op xt, cs_arm64_op src,
					     cs_arm64_op imm, size_t sz)
{
	auto t = GPR(xt.reg);
	auto base = GPR(src.mem.base);
	base->ty_ = new types::pointer_ty(new types::builtin_ty(
		types::type::INT, sz, types::signedness::UNSIGNED,
		*amd_target_));

	return SEQ(MOVE(t, MEM(base)),
		   MOVE(base, ADD(base, CNST(imm.imm), base->ty_)));
}

ir::tree::rstm lifter::arm64_handle_LDR(const disas_insn &insn, size_t sz)
{
	const cs_arm64 *mach_det = insn.mach_detail();

	cs_arm64_op xt = mach_det->operands[0];
	cs_arm64_op base = mach_det->operands[1];

	/*
	 * ldr x0, label
	 */
	if (base.type == ARM64_OP_IMM)
		return arm64_handle_LDR_imm(xt, base);

	if (mach_det->op_count == 2) {
		/*
		 * ldr x0, [x1]
		 * ldr x0, [x1, x2]
		 */
		if (is_offset_addressing(base.mem)
		    || is_base_reg_addressing(base.mem))
			return arm64_handle_LDR_reg(xt, base, sz);

		if (mach_det->writeback)
			return arm64_handle_LDR_pre(xt, base, sz);
		else
			return arm64_handle_LDR_base_offset(xt, base, sz);
	}
	if (mach_det->op_count == 3) {
		/*
		 * ldr x0, [x1], #imm
		 */
		return arm64_handle_LDR_post(xt, base, mach_det->operands[2],
					     sz);
	}

	UNREACHABLE("Unimplemented LDR form");
}

ir::tree::rstm lifter::arm64_handle_LDRH(const disas_insn &insn)
{
	return arm64_handle_LDR(insn, 2);
}

ir::tree::rstm lifter::arm64_handle_MOVK(const disas_insn &insn)
{
	const cs_arm64 *mach_det = insn.mach_detail();
	cs_arm64_op xd = mach_det->operands[0];
	cs_arm64_op imm = mach_det->operands[1];

	auto dest = GPR(xd.reg);
	auto cnst = CNST(imm.imm);

	return MOVE(dest, BINOP(BITOR, dest,
				shift(cnst, imm.shift.type, imm.shift.value),
				dest->ty_));
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

	return SEQ(MOVE(GPR(ARM64_REG_X30), CNST(insn.address() + 4)),
		   next_address(CNST(imm.imm)));
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
		flag_op::CMP);
}
ir::tree::rstm lifter::arm64_handle_CMP_reg(uint64_t address, cs_arm64_op xn,
					    cs_arm64_op xm)
{
	return set_cmp_values(address, GPR(xn.reg), GPR(xm.reg), flag_op::CMP);
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

ir::tree::rstm lifter::arm64_handle_CCMP_imm(uint64_t address, cs_arm64_op xn,
					     cs_arm64_op imm, cs_arm64_op nzcv,
					     arm64_cc cond)
{
	/*
	 * if cond then
	 *      cmp xn, imm
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
	auto set = set_cmp_values(
		address, GPR(xn.reg),
		shift(CNST(imm.imm), imm.shift.type, imm.shift.value),
		flag_op::CMP);
	auto update = set_state_field("nzcv", CNST(nzcv.imm));

	return SEQ(cj, LABEL(tcond), set, JUMP(NAME(end), {end}), LABEL(fcond),
		   update, next_address(CNST(address + 4)), LABEL(end));
}

ir::tree::rstm lifter::arm64_handle_CCMP(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xn = mach_det->operands[0];
	auto other = mach_det->operands[1];
	auto nzcv = mach_det->operands[2];
	auto cond = mach_det->cc;

	if (other.type == ARM64_OP_IMM)
		return arm64_handle_CCMP_imm(insn.address(), xn, other, nzcv,
					     cond);

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

	if (mach_det->cc == ARM64_CC_EQ)
		return cc_jump(ARM64_CC_EQ, CNST(ok_addr), CNST(fail_addr));
	if (mach_det->cc == ARM64_CC_NE)
		return cc_jump(ARM64_CC_EQ, CNST(fail_addr), CNST(ok_addr));

	UNREACHABLE("Unhandled B form");
}

ir::tree::rstm lifter::arm64_handle_STP_post(cs_arm64_op xt1, cs_arm64_op xt2,
					     cs_arm64_op xn, cs_arm64_op imm)
{
	auto r1 = GPR(xt1.reg);
	auto r2 = GPR(xt2.reg);
	auto base = GPR(xn.reg);
	utils::ref<types::ty> ptr_ty = new types::pointer_ty(r1->ty_);
	base->ty_ = ptr_ty;

	return SEQ(
		MOVE(MEM(base), r1),
		MOVE(MEM(ADD(base, CNST(r1->ty_->assem_size()), ptr_ty)), r2),
		MOVE(base,
		     ADD(GPR(xn.reg), CNST(imm.imm), arm_target_->gpr_type())));
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

	return SEQ(
		MOVE(MEM(base), r1),
		MOVE(MEM(ADD(base, CNST(r1->ty_->assem_size()), ptr_ty)), r2));
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

	return SEQ(
		MOVE(r1, MEM(base)),
		MOVE(r2, MEM(ADD(base, CNST(r1->ty_->assem_size()), ptr_ty))),
		MOVE(base,
		     ADD(GPR(xn.reg), CNST(imm.imm), arm_target_->gpr_type())));
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

	return SEQ(
		MOVE(r1, MEM(base)),
		MOVE(r2, MEM(ADD(base, CNST(r1->ty_->assem_size()), ptr_ty))));
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

	return MOVE(GPR(xd.reg), CNST(imm.imm));
}

ir::tree::rstm lifter::arm64_handle_STR_reg(cs_arm64_op xt, cs_arm64_op dst)
{
	return MOVE(GPR(xt.reg), MEM(translate_mem_op(dst.mem)));
}


ir::tree::rstm lifter::arm64_handle_STR_pre(cs_arm64_op xt, cs_arm64_op dst)
{
	auto base = GPR(dst.mem.base);

	return SEQ(arm64_handle_STR_base_offset(xt, dst),
		   MOVE(base, ADD(base, CNST(dst.mem.disp), base->ty_)));
}

ir::tree::rstm lifter::arm64_handle_STR_base_offset(cs_arm64_op xt,
						    cs_arm64_op dst)
{
	auto t = GPR(xt.reg);
	utils::ref<types::ty> ptr_ty = new types::pointer_ty(t->ty_);

	auto addr = translate_mem_op(dst.mem);
	addr->ty_ = ptr_ty;

	return MOVE(MEM(addr), t);
}

ir::tree::rstm lifter::arm64_handle_STR_post(cs_arm64_op xt, cs_arm64_op dst,
					     cs_arm64_op imm)
{
	auto t = GPR(xt.reg);
	auto base = GPR(dst.mem.base);
	utils::ref<types::ty> ptr_ty = new types::pointer_ty(t->ty_);
	base->ty_ = ptr_ty;

	return SEQ(MOVE(MEM(base), t),
		   MOVE(base, ADD(base, CNST(imm.imm), base->ty_)));
}

ir::tree::rstm lifter::arm64_handle_STR(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xt = mach_det->operands[0];
	auto dst = mach_det->operands[1];

	auto addr = translate_mem_op(dst.mem);

	if (mach_det->op_count == 2) {
		/*
		 * str x0, [x1]
		 * str x0, [x1, x2]
		 */
		if (is_offset_addressing(dst.mem)
		    || is_base_reg_addressing(dst.mem))
			return arm64_handle_STR_reg(xt, dst);
		/*
		 * str x0, [x1, #imm]!
		 * str x0, [x1, #imm]
		 */
		if (mach_det->writeback)
			return arm64_handle_STR_pre(xt, dst);
		else
			return arm64_handle_STR_base_offset(xt, dst);
	}
	if (mach_det->op_count == 3) {
		/*
		 * str x0, [x1], #imm
		 */
		return arm64_handle_STR_post(xt, dst, mach_det->operands[2]);
	}

	UNREACHABLE("Unimplemted");
}

std::tuple<ops::cmpop, ir::tree::rexp, ir::tree::rexp>
lifter::translate_cc(arm64_cc cond)
{
	auto nzcv = get_state_field("nzcv");

	ops::cmpop op;
	ir::tree::rexp lhs, rhs;

	switch (cond) {
	case ARM64_CC_EQ:
		op = ops::cmpop::EQ;
		lhs = BINOP(BITAND, nzcv, CNST(Z), amd_target_->gpr_type());
		rhs = CNST(Z);
		break;
	default:
		UNREACHABLE("Unimplemented translate_cc");
	}

	return std::make_tuple(op, lhs, rhs);
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

	auto [op, lhs, rhs] = translate_cc(cc);
	return conditional_jump(op, lhs, rhs, true_addr, false_addr);
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

	utils::label ok_label;
	utils::label fail_label;

	auto [op, lhs, rhs] = translate_cc(cc);
	return CJUMP(op, lhs, rhs, true_label, false_label);
}

ir::tree::rstm lifter::conditional_jump(ops::cmpop op, ir::tree::rexp lhs,
					ir::tree::rexp rhs,
					ir::tree::rexp true_addr,
					ir::tree::rexp false_addr)
{
	auto fail_label = make_unique("fail");
	auto ok_label = make_unique("ok");
	auto end_label = make_unique("end");

	return SEQ(CJUMP(op, lhs, rhs, ok_label, fail_label), LABEL(ok_label),
		   next_address(true_addr), JUMP(NAME(end_label), {end_label}),
		   LABEL(fail_label), next_address(false_addr),
		   LABEL(end_label));
}

ir::tree::rstm lifter::arm64_handle_CBZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xt = mach_det->operands[0];
	auto label = mach_det->operands[1];

	auto fail_addr = insn.address() + 4;

	return conditional_jump(ops::cmpop::EQ, GPR(xt.reg), CNST(0),
				CNST(label.imm), CNST(fail_addr));
}

ir::tree::rstm lifter::arm64_handle_CBNZ(const disas_insn &insn)
{
	auto *mach_det = insn.mach_detail();

	auto xt = mach_det->operands[0];
	auto label = mach_det->operands[1];

	auto fail_addr = insn.address() + 4;

	return conditional_jump(ops::cmpop::NEQ, GPR(xt.reg), CNST(0),
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

	auto [op, lhs, rhs] = translate_cc(cc);
	utils::label t, f, end;

	auto cj = CJUMP(op, lhs, rhs, t, f);

	return SEQ(cj, LABEL(t), MOVE(GPR(xd), GPR(xn)), JUMP(NAME(end), {end}),
		   LABEL(f),
		   MOVE(GPR(xd),
			BINOP(PLUS, GPR(xm), CNST(1), amd_target_->gpr_type())),
		   LABEL(end));
}

arm64_cc lifter::invert_cc(arm64_cc cc)
{
	switch (cc) {
	case ARM64_CC_EQ:
		return ARM64_CC_NE;
	case ARM64_CC_NE:
		return ARM64_CC_EQ;
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

ir::tree::rstm lifter::lift(const disas_insn &insn)
{
	switch (insn.id()) {
		HANDLER(MOV);
		HANDLER(MOVZ);
		HANDLER(ADD);
		HANDLER(LDR);
		HANDLER(LDRH);
		HANDLER(MOVK);
		HANDLER(RET);
		HANDLER(BL);
		HANDLER(CCMP);
		HANDLER(CMP);
		HANDLER(B);
		HANDLER(STP);
		HANDLER(LDP);
		HANDLER(ADRP);
		HANDLER(STR);
		HANDLER(CBZ);
		HANDLER(CBNZ);
		HANDLER(NOP);
		HANDLER(SVC);
		HANDLER(CSET);
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
		},
		{
			new types::array_ty(amd_target_->gpr_type(), 32),
			amd_target_->gpr_type(), // nzcv
			amd_target_->gpr_type(), // flag_a
			amd_target_->gpr_type(), // flag_b
			amd_target_->gpr_type(), // flag_op
			amd_target_->gpr_type(),
		});

	// fun basic_block(state* bank) int<8>
	bb_type_ =
		new types::fun_ty(amd_target_->gpr_type(),
				  {new types::pointer_ty(bank_type_)}, false);
}
} // namespace lifter
