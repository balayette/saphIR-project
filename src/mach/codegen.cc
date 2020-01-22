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
	EMIT(assem::move(repr, {ret}, {}));

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
	if (c.variadic_)
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

void generator::visit_move(tree::move &mv)
{
	if (auto lmem = mv.lhs().as<tree::mem>()) {
		if (auto rmem = mv.rhs().as<tree::mem>()) {
			// (move (mem e1) (mem e2))
			// mov (e2), e2
			// mov e2, (e1)
			lmem->e()->accept(*this);
			auto lhs = ret_;
			rmem->e()->accept(*this);
			auto rhs = ret_;

			EMIT(assem::move("mov (`s0), `d0", {rhs}, {rhs}));
			EMIT(assem::move("mov `s0, (`s1)", {}, {rhs, lhs}));
			return;
		}
		if (auto binop = lmem->e().as<tree::binop>()) {
			/*
			 * Canon guarantees that
			 * (mem (binop + a 1) (temp t)) is translated into
			 * (move (temp t2) (binop + a 1))
			 * (mem (t2) (temp t))
			 * Peephole reintroduces it in the case we're checking
			 * here.
			 * XXX: This might be a hack, and should maybe be in a
			 * mach dependant peephole opti, and not in the IR
			 * peephole... Leaving it here for the moment,
			 * because I don't have mach dependant peepholes yet,
			 * and it makes assembly output much more readable.
			 * */
			ASSERT(binop->op_ == ops::binop::PLUS, "Wrong binop");
			std::string repr("mov `s1, ");
			repr += std::to_string(
				binop->rhs().as<tree::cnst>()->value_);
			repr += "(`s0)";
			EMIT(assem::oper(repr, {},
					 {binop->lhs().as<tree::temp>()->temp_,
					  mv.rhs().as<tree::temp>()->temp_},
					 {}));
			return;
		}

		// (move (mem e1) e2)
		// mov e2, (e1)
		lmem->e()->accept(*this);
		auto lhs = ret_;
		mv.rhs()->accept(*this);
		auto rhs = ret_;

		EMIT(assem::move("mov `s0, (`s1)", {}, {rhs, lhs}));
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
	EMIT(assem::move("mov (`s0), `d0", {dst}, {ret_}));
	ret_ = dst;
}

void generator::visit_cnst(tree::cnst &c)
{
	utils::temp dst;
	std::string instr("mov $");
	instr += std::to_string(c.value_);
	instr += ", `d0";

	EMIT(assem::move(instr, {dst}, {}));

	ret_ = dst;
}

void generator::visit_temp(tree::temp &t) { ret_ = t.temp_; }

void generator::visit_binop(tree::binop &b)
{
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
