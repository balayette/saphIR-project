#include "mach/codegen.hh"
#include "utils/assert.hh"
#include "ir/visitors/ir-pretty-printer.hh"
#include "utils/misc.hh"

#include <algorithm>
#include <sstream>

using namespace ir;

/*
 * The generator heavily relies on the register allocator to remove redundant
 * moves, and makes little effort to limit the temporary use.
 */

#define EMIT(x)                                                                \
	do {                                                                   \
		emit(new x);                                                   \
	} while (0)

namespace mach
{

std::string label_to_asm(const utils::label &lbl)
{
	std::string ret(".L_");
	ret += lbl;

	return ret;
}

assem::temp reg_to_assem_temp(mach::regs t) { return reg_to_temp(t); }
assem::temp
reg_to_assem_temp(mach::regs t, unsigned sz,
		  types::signedness is_signed = types::signedness::SIGNED)
{
	auto tmp = reg_to_assem_temp(t);
	tmp.size_ = sz;
	tmp.is_signed_ = is_signed;
	return tmp;
}

std::vector<assem::rinstr> codegen(mach::frame &f, tree::rnodevec instrs)
{
	generator g;
	(void)f;

	for (auto &i : instrs)
		i->accept(g);

	return g.instrs_;
}

void generator::visit_name(tree::name &n)
{
	assem::temp ret;
	EMIT(assem::lea(ret, label_to_asm(n.label_) + "(%rip)"));

	ret_ = ret;
}

void generator::visit_call(tree::call &c)
{
	auto name = c.name().as<tree::name>()->label_;
	std::vector<assem::temp> src;
	auto cc = args_regs();
	auto args = c.args();

	size_t reg_args_count = std::min(args.size(), cc.size());
	size_t stack_args_count =
		args.size() > cc.size() ? args.size() - cc.size() : 0;
	size_t stack_space = stack_args_count * 8;
	// The stack must be 16 bytes aligned.
	size_t alignment_bonus = ROUND_UP(stack_space, 16) - stack_space;
	size_t total_stack_change = stack_space + alignment_bonus;

	if (alignment_bonus)
		EMIT(assem::oper("subq $" + std::to_string(alignment_bonus)
					 + ", %rsp",
				 {}, {}, {}));

	// Push stack parameters RTL
	for (size_t i = 0; i < stack_args_count; i++) {
		args[args.size() - 1 - i]->accept(*this);
		EMIT(assem::oper("push `s0", {}, {assem::temp(ret_, 8)}, {}));
	}

	// Move registers params to the correct registers.
	for (size_t i = 0; i < reg_args_count; i++) {
		args[i]->accept(*this);
		src.push_back(cc[i]);
		/*
		 * Function parameters < 32 bits must be extended to 32 bits,
		 * according to GCC. This is not necessary according to the
		 * System V ABI, but GCC is all that matters anyways...
		 */

		// In a variadic function
		if (i >= c.fun_ty_->arg_tys_.size()) {
			EMIT(assem::simple_move(
				assem::temp(cc[i], std::max(ret_.size_, 4u),
					    ret_.is_signed_),
				ret_));
		} else
			EMIT(assem::simple_move(
				assem::temp(cc[i], std::max(ret_.size_, 4u),
					    c.fun_ty_->arg_tys_[i]
						    ->get_signedness()),
				ret_));
	}

	// XXX: %al holds the number of floating point variadic parameters.
	// This assumes no floating point parameters
	if (c.variadic())
		EMIT(assem::oper("xor `d0, `d0",
				 {reg_to_assem_temp(regs::RAX, 1)}, {}, {}));

	std::string repr("call ");
	repr += name.get() + "@PLT";

	auto clobbered_regs = mach::caller_saved_regs();
	auto args_regs = mach::args_regs();

	std::vector<assem::temp> clobbered;
	clobbered.insert(clobbered.end(), clobbered_regs.begin(),
			 clobbered_regs.end());
	clobbered.insert(clobbered.end(), args_regs.begin(), args_regs.end());

	EMIT(assem::oper(repr, clobbered, src, {}));
	if (total_stack_change)
		EMIT(assem::oper("addq $" + std::to_string(total_stack_change)
					 + ", %rsp",
				 {}, {}, {}));

	assem::temp ret(c.ty_->assem_size());
	if (ret.size_ != 0)
		EMIT(assem::simple_move(ret, reg_to_assem_temp(regs::RAX)));

	// XXX: The temp is not initialized if the function doesn't return
	// a value, but sema makes sure that void function results aren't used
	ret_ = ret;
}

void generator::visit_cjump(tree::cjump &cj)
{
	auto cmp_sz = std::max(cj.lhs()->assem_size(), cj.rhs()->assem_size());

	cj.lhs()->accept(*this);
	auto lhs = ret_;
	cj.rhs()->accept(*this);
	auto rhs = ret_;

	assem::temp cmpr(cmp_sz, lhs.is_signed_);
	assem::temp cmpl(cmp_sz, rhs.is_signed_);

	EMIT(assem::simple_move(cmpr, rhs));
	EMIT(assem::simple_move(cmpl, lhs));

	EMIT(assem::sized_oper("cmp", "`s0, `s1", {}, {cmpr, cmpl}, cmp_sz));
	std::string repr;
	if (cj.op_ == ops::cmpop::EQ)
		repr += "je ";
	else if (cj.op_ == ops::cmpop::NEQ)
		repr += "jne ";
	else if (cj.op_ == ops::cmpop::SMLR)
		repr += "jl ";
	else if (cj.op_ == ops::cmpop::GRTR)
		repr += "jg ";
	else if (cj.op_ == ops::cmpop::SMLR_EQ)
		repr += "jle ";
	else if (cj.op_ == ops::cmpop::GRTR_EQ)
		repr += "jge ";
	else
		UNREACHABLE("Impossible cmpop");

	repr += label_to_asm(cj.ltrue_);
	EMIT(assem::oper(repr, {}, {}, {cj.ltrue_, cj.lfalse_}));
}

void generator::visit_label(tree::label &l)
{
	EMIT(assem::label(label_to_asm(l.name_) + std::string(":"), l.name_));
}

void generator::visit_jump(tree::jump &j)
{
	if (auto dest = j.dest().as<tree::name>()) {
		std::string repr("jmp ");
		repr += label_to_asm(dest->label_);

		EMIT(assem::oper(repr, {}, {}, {dest->label_}));
	} else
		UNREACHABLE("Destination of jump must be a name");
}

// matches (temp t)
bool is_reg(tree::rexp e) { return e.as<tree::temp>() != nullptr; }

// matches (temp t) and (cnst x)
bool is_simple_source(tree::rexp e)
{
	return is_reg(e) || e.as<tree::cnst>() != nullptr;
}

// matches (binop + (temp t) (cnst x))
// if check_ty is true, and the type of the binop is not a pointer type,
// then don't match.
bool is_reg_disp(tree::rexp e, bool check_ty = false)
{
	auto binop = e.as<tree::binop>();
	if (!binop || binop->op_ != ops::binop::PLUS)
		return false;

	// try to only use lea when dealing with pointers and structs
	if (check_ty
	    && (!binop->ty_.as<types::pointer_ty>()
		|| !binop->ty_.as<types::struct_ty>()))
		return false;

	auto reg = binop->lhs().as<tree::temp>();
	auto cnst = binop->rhs().as<tree::cnst>();

	if (!reg || !cnst)
		return false;

	return true;
}

std::pair<std::string, assem::temp> reg_deref_str(tree::rexp e,
						  std::string regstr)
{
	if (is_reg_disp(e)) {
		auto binop = e.as<tree::binop>();
		auto reg = binop->lhs().as<tree::temp>();
		auto cnst = binop->rhs().as<tree::cnst>();

		return {std::to_string(cnst->value_) + "(" + regstr + ")",
			reg->temp_};
	} else if (is_reg(e)) {
		auto reg = e.as<tree::temp>();
		return {"(" + regstr + ")", reg->temp_};
	}

	UNREACHABLE("what");
}

std::pair<std::string, std::optional<assem::temp>>
simple_src_str(tree::rexp e, std::string regstr)
{
	auto reg = e.as<tree::temp>();
	if (reg)
		return {regstr, assem::temp(reg->temp_, e->ty_->assem_size(),
					    e->ty_->get_signedness())};

	auto cnst = e.as<tree::cnst>();
	if (cnst)
		return {"$" + std::to_string(cnst->value_), std::nullopt};

	UNREACHABLE("simple_src is a reg or cnst");
}

// matches (mem (temp t)) and (mem (binop + (temp t) (cnst x)))
bool is_mem_reg(tree::rexp e)
{
	auto mem = e.as<tree::mem>();
	return mem && (is_reg(mem->e()) || is_reg_disp(mem->e()));
}

/*
 * Move codegen cases and expected output
 * All (binop + (temp t) (cnst x)) can also be a simple (temp t) node except
 * in the lea case
 *
 * (move (temp t1) (temp t2))
 *      => mov %t2, %t1
 *
 * (move (temp t1) (binop + (temp t2) (cnst 3)))
 *      => lea 3(%t2), %t1
 *
 * (move (temp t1) (mem (binop + (temp t2) (cnst 3))))
 *      => mov 3(%t2), %t1
 *
 * (move (mem (binop + (temp t1) (cnst 3))) (temp t2))
 *      => mov %t2, 3(%t1)
 *
 * (move (mem (binop + (temp t1) (cnst 3))) (mem (binop + (temp t2) (cnst 4))))
 *      Split
 *      (move t3 (mem (binop + (temp t2) (cnst 4))))
 *      (move (mem (binop + (temp t1) (cnst 3))) t3)
 *      =>
 *      mov 4(%t2), %t3
 *      mov %t3, 3(%t1)
 *
 * All other cases aren't optimized
 */

void generator::visit_move(tree::move &mv)
{
	auto signedness = mv.lhs()->ty_->get_signedness();

	if (is_reg(mv.lhs()) && is_reg_disp(mv.rhs(), true)) {
		// lea 3(%t2), %t1
		auto t1 = assem::temp(mv.lhs().as<tree::temp>()->temp_,
				      mv.lhs()->ty_->assem_size(), signedness);

		auto [s, t2] = reg_deref_str(mv.rhs(), "`s0");

		EMIT(assem::lea(t1, {s, t2}));
		return;
	}
	if (is_reg(mv.lhs()) && is_mem_reg(mv.rhs())) {
		// mov 3(%t2), %t1
		auto t1 = assem::temp(mv.lhs().as<tree::temp>()->temp_,
				      mv.lhs()->ty_->assem_size(),
				      mv.lhs()->ty_->get_signedness());

		auto mem = mv.rhs().as<tree::mem>();
		auto [s, t2] = reg_deref_str(mem->e(), "`s0");

		EMIT(assem::complex_move("`d0", s, {t1}, {t2},
					 mv.lhs()->assem_size(),
					 mv.rhs()->assem_size(), signedness));
		return;
	}
	if (is_mem_reg(mv.lhs()) && is_simple_source(mv.rhs())) {
		// mov %t2, 3(%t1)
		auto [s1, t2] = simple_src_str(mv.rhs(), "`s0");

		auto mem = mv.lhs().as<tree::mem>();
		auto [s2, t1] = reg_deref_str(
			mem->e(), t2 == std::nullopt ? "`s0" : "`s1");

		if (t2 == std::nullopt)
			EMIT(assem::complex_move(
				s2, s1, {}, {t1}, mv.lhs()->assem_size(),
				mv.rhs()->assem_size(), signedness));
		else
			EMIT(assem::complex_move(
				s2, s1, {}, {*t2, t1}, mv.lhs()->assem_size(),
				mv.rhs()->assem_size(), signedness));
		return;
	}
	if (is_mem_reg(mv.lhs()) && is_mem_reg(mv.rhs())) {
		// mov 4(%t2), %t3
		// mov %t3, 3(%t1)

		// t3 is the same size as the destination
		assem::temp t3(mv.lhs()->ty_->assem_size());

		auto mem1 = mv.rhs().as<tree::mem>();
		auto [s1, t2] = reg_deref_str(mem1->e(), "`s0");
		EMIT(assem::complex_move("`d0", s1, {t3}, {t2},
					 mv.lhs()->assem_size(),
					 mv.rhs()->assem_size(), signedness));

		auto mem2 = mv.lhs().as<tree::mem>();
		auto [s2, t1] = reg_deref_str(mem2->e(), "`s1");
		EMIT(assem::complex_move(s2, "`s0", {}, {t3, t1},
					 mv.lhs()->assem_size(),
					 mv.rhs()->assem_size(), signedness));
		return;
	}

	if (auto lmem = mv.lhs().as<tree::mem>()) {
		// (move (mem e1) e2)
		// mov e2, (e1)
		lmem->e()->accept(*this);
		auto lhs = ret_;
		mv.rhs()->accept(*this);
		auto rhs = assem::temp(ret_, mv.lhs()->assem_size());

		EMIT(assem::complex_move("(`s1)", "`s0", {}, {rhs, lhs},
					 mv.lhs()->assem_size(),
					 mv.lhs()->assem_size(), signedness));
		return;
	}

	mv.lhs()->accept(*this);
	auto lhs = assem::temp(ret_, mv.lhs()->assem_size(), signedness);
	mv.rhs()->accept(*this);
	auto rhs = assem::temp(ret_, mv.rhs()->assem_size(), signedness);

	EMIT(assem::simple_move(lhs, rhs));
}

void generator::visit_mem(tree::mem &mm)
{
	assem::temp dst(mm.ty_->assem_size());

	mm.e()->accept(*this);
	EMIT(assem::complex_move("`d0", "(`s0)", {dst}, {ret_},
				 mm.ty_->assem_size(), mm.ty_->assem_size(),
				 types::signedness::INVALID));
	ret_ = dst;
}

void generator::visit_cnst(tree::cnst &c)
{
	assem::temp dst;

	EMIT(assem::complex_move("`d0", "$" + std::to_string(c.value_), {dst},
				 {}, 8, 8, types::signedness::INVALID));

	ret_ = dst;
}

void generator::visit_temp(tree::temp &t)
{
	ret_ = assem::temp(t.temp_, t.assem_size(), t.ty_->get_signedness());
}

bool generator::opt_mul(tree::binop &b)
{
	ASSERT(b.op_ == ops::binop::MULT, "not mult node");
	auto cnst = b.rhs().as<tree::cnst>();
	if (!cnst)
		return false;

	b.lhs()->accept(*this);
	auto lhs = ret_;

	std::string repr("$");
	repr += std::to_string(cnst->value_);
	repr += ", `d0";

	assem::temp dst;

	EMIT(assem::simple_move(dst, lhs));
	EMIT(assem::sized_oper("imul", repr, {dst}, {lhs}, 8));

	ret_ = dst;

	return true;
}

bool generator::opt_add(tree::binop &b)
{
	ASSERT(b.op_ == ops::binop::PLUS, "not add node");
	auto cnst = b.rhs().as<tree::cnst>();
	if (!cnst)
		return false;

	b.lhs()->accept(*this);
	auto lhs = ret_;

	std::string repr("$");
	repr += std::to_string(cnst->value_);
	repr += ", `d0";

	assem::temp dst;
	EMIT(assem::simple_move(dst, lhs));
	if (cnst->value_ != 0)
		EMIT(assem::sized_oper("add", repr, {dst}, {lhs}, 8));

	ret_ = dst;

	return true;
}

void generator::visit_binop(tree::binop &b)
{
	if (b.op_ == ops::binop::PLUS && opt_add(b))
		return;
	else if (b.op_ == ops::binop::MULT && opt_mul(b))
		return;

	auto oper_sz = std::max(b.lhs()->assem_size(), b.rhs()->assem_size());
	if (b.op_ == ops::binop::MULT)
		oper_sz = std::max(oper_sz, 2ul); // imul starts at r16
	if (b.op_ == ops::binop::BITLSHIFT || b.op_ == ops::binop::BITRSHIFT
	    || b.op_ == ops::binop::ARITHBITRSHIFT)
		oper_sz = b.lhs()->assem_size();

	b.lhs()->accept(*this);
	auto lhs = assem::temp(oper_sz);
	EMIT(assem::simple_move(lhs, ret_));

	b.rhs()->accept(*this);
	auto rhs = assem::temp(oper_sz);
	EMIT(assem::simple_move(rhs, ret_));

	assem::temp dst(oper_sz);

	if (b.op_ != ops::binop::MINUS && b.op_ != ops::binop::BITLSHIFT
	    && b.op_ != ops::binop::BITRSHIFT
	    && b.op_ != ops::binop::ARITHBITRSHIFT)
		EMIT(assem::simple_move(dst, rhs));
	else
		EMIT(assem::simple_move(dst, lhs));

	if (b.op_ == ops::binop::PLUS)
		EMIT(assem::sized_oper("add", "`s0, `d0", {dst}, {lhs, dst},
				       oper_sz));
	else if (b.op_ == ops::binop::MINUS)
		EMIT(assem::sized_oper("sub", "`s0, `d0", {dst}, {rhs, dst},
				       oper_sz));
	else if (b.op_ == ops::binop::MULT)
		EMIT(assem::sized_oper("imul", "`s0, `d0", {dst}, {lhs},
				       oper_sz));
	else if (b.op_ == ops::binop::BITXOR)
		EMIT(assem::sized_oper("xor", "`s0, `d0", {dst}, {lhs, dst},
				       oper_sz));
	else if (b.op_ == ops::binop::BITAND)
		EMIT(assem::sized_oper("and", "`s0, `d0", {dst}, {lhs, dst},
				       oper_sz));
	else if (b.op_ == ops::binop::BITOR)
		EMIT(assem::sized_oper("or", "`s0, `d0", {dst}, {lhs, dst},
				       oper_sz));
	else if (b.op_ == ops::binop::BITLSHIFT) {
		/*
		 * shlX %cl, %reg is the only encoding for all sizes of reg
		 */
		auto cl = reg_to_assem_temp(regs::RCX, 1);
		EMIT(assem::simple_move(cl, rhs));
		EMIT(assem::sized_oper("shl", "`s0, `d0", {dst}, {cl, dst},
				       oper_sz));
	} else if (b.op_ == ops::binop::BITRSHIFT) {
		/*
		 * shrX %cl, %reg is the only encoding for all sizes of reg
		 */
		auto cl = reg_to_assem_temp(regs::RCX, 1);
		EMIT(assem::simple_move(cl, rhs));
		EMIT(assem::sized_oper("shr", "`s0, `d0", {dst}, {cl, dst},
				       oper_sz));
	} else if (b.op_ == ops::binop::ARITHBITRSHIFT) {
		/*
		 * sarX %cl, %reg is the only encoding for all sizes of reg
		 */
		auto cl = reg_to_assem_temp(regs::RCX, 1);
		EMIT(assem::simple_move(cl, rhs));
		EMIT(assem::sized_oper("sar", "`s0, `d0", {dst}, {cl, dst},
				       oper_sz));
	} else if (b.op_ == ops::binop::DIV || b.op_ == ops::binop::MOD) {
		EMIT(assem::simple_move(reg_to_assem_temp(regs::RAX), lhs));
		EMIT(assem::oper("cqto",
				 {reg_to_assem_temp(regs::RAX),
				  reg_to_assem_temp(regs::RDX)},
				 {reg_to_assem_temp(regs::RAX)}, {}));
		// quotient in %rax, remainder in %rdx
		EMIT(assem::oper("idivq `s0",
				 {reg_to_assem_temp(regs::RAX),
				  reg_to_assem_temp(regs::RDX)},
				 {dst, reg_to_assem_temp(regs::RAX),
				  reg_to_assem_temp(regs::RAX)},
				 {}));
		if (b.op_ == ops::binop::DIV)
			EMIT(assem::simple_move(
				dst, reg_to_assem_temp(regs::RAX, oper_sz)));
		else
			EMIT(assem::simple_move(
				dst, reg_to_assem_temp(regs::RDX, oper_sz)));
	} else
		UNREACHABLE("Unimplemented binop");

	ret_ = dst;
}

void generator::visit_unaryop(tree::unaryop &b)
{
	b.e()->accept(*this);
	auto val = ret_;

	if (b.op_ == ops::unaryop::NOT) {
		/*
		 * System V wants bools where the least significant bit
		 * is 0/1 and all the other bits are 0. This means that
		 * we need to zero the register before potentially
		 * setting the least significant bit.
		 * Zero'ing only the lowest byte of a register introduces
		 * a dependency on the high bytes, so we zero the entire
		 * register.
		 */
		assem::temp dst(4, types::signedness::UNSIGNED);
		EMIT(assem::sized_oper("xor", "`d0, `d0", {dst}, {}, 4));
		EMIT(assem::sized_oper("cmp", "$0x0, `s0", {}, {val},
				       b.e()->assem_size()));
		dst.size_ = 1;
		EMIT(assem::oper("sete `d0", {dst}, {}, {}));
		ret_ = dst;
	} else if (b.op_ == ops::unaryop::NEG) {
		assem::temp dst(b.ty_->size(), val.is_signed_);
		EMIT(assem::simple_move(dst, val));
		EMIT(assem::oper("neg `s0", {dst}, {dst}, {}));
		ret_ = dst;
	} else if (b.op_ == ops::unaryop::BITNOT) {
		assem::temp dst(b.ty_->size(), val.is_signed_);
		EMIT(assem::simple_move(dst, val));
		EMIT(assem::oper("not `s0", {dst}, {dst}, {}));
		ret_ = dst;
	} else
		UNREACHABLE("Unimplemented unaryop\n");
}

void generator::emit(assem::rinstr ins)
{
	unsigned width = 80;
	std::stringstream str;
	str << ins->repr();

	while (str.str().size() <= width / 2)
		str << " ";
	if (ins->jmps_.size() > 0)
		str << " # Jumps:";
	for (auto lb : ins->jmps_)
		str << " " << lb;

	while (str.str().size() < width)
		str << " ";
	str << "| ";
	str << ins->to_string() << '\n';

	std::cout << str.str();

	instrs_.push_back(ins);
}
} // namespace mach
