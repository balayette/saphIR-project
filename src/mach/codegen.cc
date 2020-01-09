#include "mach/codegen.hh"
#include "utils/assert.hh"
#include "ir/visitors/ir-pretty-printer.hh"

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
	ret += lbl.get();

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
	unsigned i = 0;
	std::vector<utils::temp> src;
	auto cc = args_regs();
	ASSERT(c.args().size() <= cc.size(), "Too many function parameters.");
	for (auto arg : c.args()) {
		arg->accept(*this);
		auto arglbl = ret_;
		auto dest = cc[i];
		src.push_back(arglbl);

		std::string repr("mov `s0, `d0");

		EMIT(assem::move(repr, {dest}, {arglbl}));
		i++;
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

	EMIT(assem::oper("cmp `s0, `s1", {}, {lhs, rhs}, {}));
	std::string repr;
	if (cj.op_ == ops::cmpop::EQ) {
		repr += "je ";
		repr += label_to_asm(cj.ltrue_);
	} else if (cj.op_ == ops::cmpop::NEQ) {
		repr += "jne ";
		repr += label_to_asm(cj.ltrue_);

	} else
		UNREACHABLE("Impossible cmpop");

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
	mm.e()->accept(*this);
	utils::temp dst;
	EMIT(assem::move("mov (`s0), `d0", {dst}, {ret_}));
	ret_ = dst;
}

void generator::visit_cnst(tree::cnst &c)
{
	utils::temp dst;
	if (c.value_ == 0) {
		EMIT(assem::oper("xor `d0, `d0", {dst}, {}, {}));
	} else {
		std::string instr("mov $");
		instr += std::to_string(c.value_);
		instr += ", `d0";

		EMIT(assem::move(instr, {dst}, {}));
	}

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

	EMIT(assem::move("mov `s0, `d0", {dst}, {rhs}));
	if (b.op_ == ops::binop::PLUS)
		EMIT(assem::oper("add `s0, `d0", {dst}, {lhs, dst}, {}));
	else if (b.op_ == ops::binop::MINUS)
		EMIT(assem::oper("sub `s0, `d0", {dst}, {lhs, dst}, {}));

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
