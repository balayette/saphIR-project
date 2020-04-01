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

std::vector<assem::rinstr> codegen(mach::frame &f, tree::rnodevec instrs)
{
	generator g;
	(void)f;

	for (auto &i : instrs) {
		/*
		ir::ir_pretty_printer p(std::cout);
		std::cout << "#####\n";
		i->accept(p);
		*/
		i->accept(g);
	}

	return g.instrs_;
}

void generator::visit_name(tree::name &n)
{
	std::string repr("lea ");
	repr += label_to_asm(n.label_);
	repr += "(%rip), `d0";

	utils::temp ret;
	EMIT(assem::oper(repr, {ret}, {}, {}));

	ret_ = ret;
}

void generator::visit_call(tree::call &c)
{
	auto name = c.name().as<tree::name>()->label_;
	std::vector<utils::temp> src;
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
		src.push_back(ret_);
		EMIT(assem::oper("push `s0", {}, {ret_}, {}));
	}
	// Move registers params to the correct registers.
	for (size_t i = 0; i < reg_args_count; i++) {
		args[i]->accept(*this);
		src.push_back(ret_);
		EMIT(assem::move("mov `s0, `d0", {cc[i]}, {ret_}));
	}

	// XXX: This assumes no floating point parameters
	if (c.variadic())
		EMIT(assem::oper("xor `d0, `d0", {reg_to_temp(regs::RAX)}, {},
				 {}));

	std::string repr("call ");
	repr += name.get() + "@PLT";

	auto clobbered = mach::caller_saved_regs();
	auto args_regs = mach::args_regs();
	clobbered.insert(clobbered.end(), args_regs.begin(), args_regs.end());

	EMIT(assem::oper(repr, clobbered, src, {}));
	if (total_stack_change)
		EMIT(assem::oper("addq $" + std::to_string(total_stack_change)
					 + ", %rsp",
				 {}, {}, {}));

	utils::temp ret;
	EMIT(assem::move("mov `s0, `d0", {ret}, {reg_to_temp(regs::RAX)}));

	// XXX: The last move is not necessary if (sexp (call))
	ret_ = ret;
}

void generator::visit_cjump(tree::cjump &cj)
{
	cj.lhs()->accept(*this);
	auto lhs = ret_;
	cj.rhs()->accept(*this);
	auto rhs = ret_;

	EMIT(assem::oper("cmp `s0, `s1", {}, {rhs, lhs}, {}));
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

std::pair<std::string, utils::temp> reg_deref_str(tree::rexp e,
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

std::pair<std::string, std::optional<utils::temp>>
simple_src_str(tree::rexp e, std::string regstr)
{
	auto reg = e.as<tree::temp>();
	if (reg)
		return {regstr, reg->temp_};

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
	std::cout << "===== MOVE ======\n";
	ir::ir_pretty_printer pir(std::cout);
	mv.accept(pir);

	if (is_reg(mv.lhs()) && is_simple_source(mv.rhs())) {
		// mov %t2, %t1
		auto t1 = mv.lhs().as<tree::temp>()->temp_;
		auto [s, t2] = simple_src_str(mv.rhs(), "`s0");

		/*
		 * Technically, this isn't necessary, because not doing it
		 * would generate
		 * mov $x, ntemp
		 * mov temp, t1
		 * Which the register allocator easily optimizes, but I am
		 * leaving it here for good measure.
		 */
		if (t2 == std::nullopt)
			EMIT(assem::move("mov " + s + ", `d0", {t1}, {}));
		else
			EMIT(assem::move("mov `s0, `d0", {t1}, {*t2}));
		return;
	}
	if (is_reg(mv.lhs()) && is_reg_disp(mv.rhs(), false)) {
		// lea 3(%t2), %t1
		auto t1 = mv.lhs().as<tree::temp>()->temp_;
		auto [s, t2] = reg_deref_str(mv.rhs(), "`s0");

		EMIT(assem::oper("lea " + s + ", `d0", {t1}, {t2}, {}));
		return;
	}
	if (is_reg(mv.lhs()) && is_mem_reg(mv.rhs())) {
		// mov 3(%t2), %t1
		auto t1 = mv.lhs().as<tree::temp>()->temp_;

		auto mem = mv.rhs().as<tree::mem>();
		auto [s, t2] = reg_deref_str(mem->e(), "`s0");

		EMIT(assem::oper("mov " + s + ", `d0", {t1}, {t2}, {}));
		return;
	}
	if (is_mem_reg(mv.lhs()) && is_simple_source(mv.rhs())) {
		// mov %t2, 3(%t1)
		auto [s1, t2] = simple_src_str(mv.rhs(), "`s0");

		auto mem = mv.lhs().as<tree::mem>();
		auto [s2, t1] = reg_deref_str(
			mem->e(), t2 == std::nullopt ? "`s0" : "`s1");

		if (t2 == std::nullopt)
			EMIT(assem::oper("movq " + s1 + ", " + s2, {}, {t1},
					 {}));
		else
			EMIT(assem::oper("movq " + s1 + ", " + s2, {},
					 {*t2, t1}, {}));
		return;
	}
	if (is_mem_reg(mv.lhs()) && is_mem_reg(mv.rhs())) {
		// mov 4(%t2), %t3
		// mov %t3, 3(%t1)
		utils::temp t3;
		auto mem1 = mv.rhs().as<tree::mem>();
		auto [s1, t2] = reg_deref_str(mem1->e(), "`s0");
		EMIT(assem::oper("mov " + s1 + ", `d0", {t3}, {t2}, {}));

		auto mem2 = mv.lhs().as<tree::mem>();
		auto [s2, t1] = reg_deref_str(mem2->e(), "`s1");
		EMIT(assem::oper("mov `s0, " + s2, {}, {t3, t1}, {}));
		return;
	}

	std::cout << "default\n";
	if (auto lmem = mv.lhs().as<tree::mem>()) {
		// (move (mem e1) e2)
		// mov e2, (e1)
		lmem->e()->accept(*this);
		auto lhs = ret_;
		mv.rhs()->accept(*this);
		auto rhs = ret_;

		EMIT(assem::oper("mov `s0, (`s1)", {}, {rhs, lhs}, {}));
		return;
	}

	mv.lhs()->accept(*this);
	auto lhs = ret_;
	mv.rhs()->accept(*this);
	auto rhs = ret_;

	EMIT(assem::move("mov `s0, `d0", {lhs}, {rhs}));
}

void generator::visit_mem(tree::mem &mm)
{
	utils::temp dst;

	if (auto binop = mm.e().as<tree::binop>()) {
		if (auto reg = binop->lhs().as<tree::temp>()) {
			if (mach::temp_map().count(reg->temp_)) {
				if (auto n = binop->rhs().as<tree::cnst>()) {
					std::string repr("mov ");
					repr += std::to_string(n->value_);
					repr += "(`s0), `d0";

					EMIT(assem::oper(repr, {dst},
							 {reg->temp_}, {}));
					ret_ = dst;
					return;
				}
			}
		}
	}

	mm.e()->accept(*this);
	EMIT(assem::oper("mov (`s0), `d0", {dst}, {ret_}, {}));
	ret_ = dst;
}

void generator::visit_cnst(tree::cnst &c)
{
	utils::temp dst;
	std::string instr("mov $");
	instr += std::to_string(c.value_);
	instr += ", `d0";

	EMIT(assem::oper(instr, {dst}, {}, {}));

	ret_ = dst;
}

void generator::visit_temp(tree::temp &t) { ret_ = t.temp_; }

bool generator::opt_mul(tree::binop &b)
{
	ASSERT(b.op_ == ops::binop::MULT, "not mult node");
	auto cnst = b.rhs().as<tree::cnst>();
	if (!cnst)
		return false;

	b.lhs()->accept(*this);
	auto lhs = ret_;

	std::string repr("imulq $");
	repr += std::to_string(cnst->value_);
	repr += ", `d0";

	utils::temp dst;
	EMIT(assem::move("mov `s0, `d0", {dst}, {lhs}));

	EMIT(assem::oper(repr, {dst}, {lhs}, {}));

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

	std::string repr("add $");
	repr += std::to_string(cnst->value_);
	repr += ", `d0";

	utils::temp dst;
	EMIT(assem::move("mov `s0, `d0", {dst}, {lhs}));

	if (cnst->value_ != 0)
		EMIT(assem::oper(repr, {dst}, {lhs}, {}));

	ret_ = dst;

	return true;
}

void generator::visit_binop(tree::binop &b)
{
	if (b.op_ == ops::binop::PLUS && opt_add(b))
		return;
	else if (b.op_ == ops::binop::MULT && opt_mul(b))
		return;

	b.lhs()->accept(*this);
	auto lhs = ret_;
	b.rhs()->accept(*this);
	auto rhs = ret_;

	utils::temp dst;

	if (b.op_ != ops::binop::MINUS)
		EMIT(assem::move("mov `s0, `d0", {dst}, {rhs}));
	else
		EMIT(assem::move("mov `s0, `d0", {dst}, {lhs}));

	if (b.op_ == ops::binop::PLUS)
		EMIT(assem::oper("add `s0, `d0", {dst}, {lhs, dst}, {}));
	else if (b.op_ == ops::binop::MINUS)
		EMIT(assem::oper("sub `s0, `d0", {dst}, {rhs, dst}, {}));
	else if (b.op_ == ops::binop::MULT)
		EMIT(assem::oper("imulq `s0, `d0", {dst}, {lhs}, {}));
	else if (b.op_ == ops::binop::BITXOR)
		EMIT(assem::oper("xor `s0, `d0", {dst}, {lhs, dst}, {}));
	else if (b.op_ == ops::binop::BITAND)
		EMIT(assem::oper("and `s0, `d0", {dst}, {lhs, dst}, {}));
	else if (b.op_ == ops::binop::BITOR)
		EMIT(assem::oper("or `s0, `d0", {dst}, {lhs, dst}, {}));
	else if (b.op_ == ops::binop::DIV || b.op_ == ops::binop::MOD) {
		EMIT(assem::move("mov `s0, `d0", {reg_to_temp(regs::RAX)},
				 {lhs}));
		EMIT(assem::oper(
			"cqto",
			{reg_to_temp(regs::RAX), reg_to_temp(regs::RDX)},
			{reg_to_temp(regs::RAX)}, {}));
		// quotient in %rax, remainder in %rdx
		EMIT(assem::oper(
			"idivq `s0",
			{reg_to_temp(regs::RAX), reg_to_temp(regs::RDX)},
			{dst, reg_to_temp(regs::RAX), reg_to_temp(regs::RAX)},
			{}));
		if (b.op_ == ops::binop::DIV)
			EMIT(assem::move("mov `s0, `d0", {dst},
					 {reg_to_temp(regs::RAX)}));
		else
			EMIT(assem::move("mov `s0, `d0", {dst},
					 {reg_to_temp(regs::RDX)}));
	} else
		UNREACHABLE("Unimplemented binop");

	ret_ = dst;
}

void generator::emit(assem::rinstr ins)
{
	unsigned width = 50;
	std::stringstream str;
	str << ins->repr_;

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
