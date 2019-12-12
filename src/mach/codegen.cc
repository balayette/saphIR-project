#include "mach/codegen.hh"
#include "ir/visitors/default-ir-visitor.hh"
#include "ir/visitors/ir-pretty-printer.hh"

using namespace ir;

/*
 * The generator heavily relies on the register allocator to remove redundant
 * moves, and makes little effort to limit the temporary use.
 */

namespace mach
{

std::string label_to_asm(const ::temp::label &lbl)
{
	std::string ret(".L_");
	ret += lbl.sym_.get();

	return ret;
}

struct generator : public default_ir_visitor {
	void emit(const assem::instr &i);

	void visit_cnst(tree::cnst &) override;
	// void visit_name(tree::name &) override;
	void visit_temp(tree::temp &) override;
	void visit_binop(tree::binop &) override;
	void visit_mem(tree::mem &) override;
	// void visit_call(tree::call &n) override;
	void visit_move(tree::move &) override;
	// void visit_sexp(tree::sexp &n) override;
	void visit_jump(tree::jump &) override;
	void visit_cjump(tree::cjump &) override;
	void visit_label(tree::label &) override;

	std::vector<assem::instr> instrs_;
	::temp::temp ret_;
};

std::vector<assem::instr> codegen(frame::frame &f, tree::rnodevec instrs)
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
void generator::visit_cjump(tree::cjump &cj)
{
	cj.lhs()->accept(*this);
	auto lhs = ret_;
	cj.rhs()->accept(*this);
	auto rhs = ret_;

	emit(assem::oper("cmp `s0, `s1", {}, {lhs, rhs}, {}));
	std::string repr;
	if (cj.op_ == ops::cmpop::EQ) {
		repr += "jeq ";
		repr += label_to_asm(cj.ltrue_);
	} else if (cj.op_ == ops::cmpop::NEQ) {
		repr += "jne ";
		repr += label_to_asm(cj.ltrue_);

	} else
		repr += "INVALID JUMP";

	emit(assem::instr(repr, {}, {}, {cj.ltrue_, cj.lfalse_}));
}

void generator::visit_label(tree::label &l)
{
	emit(assem::label(label_to_asm(l.name_) + std::string(":"), l.name_));
}

void generator::visit_jump(tree::jump &j)
{
	if (auto dest = j.dest().as<tree::name>()) {
		std::string repr("jmp ");
		repr += label_to_asm(dest->label_);

		emit(assem::oper(repr, {}, {}, {dest->label_}));
	} else
		emit(assem::oper("BADJUMP", {}, {}, {}));
}

void generator::visit_move(tree::move &mv)
{
	if (auto lmem = mv.lhs().as<tree::mem>()) {
		if (auto rmem = mv.lhs().as<tree::mem>()) {
			// (move (mem e1) (mem e2))
			// mov (e2), e2
			// mov e2, (e1)
			lmem->e()->accept(*this);
			auto lhs = ret_;
			rmem->e()->accept(*this);
			auto rhs = ret_;

			emit(assem::move("mov (`s0), `d0", {rhs}, {rhs}));
			emit(assem::move("mov `s0, (`d0)", {lhs}, {rhs}));
			return;
		}

		// (move (mem e1) e2)
		// mov e2, (e1)
		lmem->e()->accept(*this);
		auto lhs = ret_;
		mv.rhs()->accept(*this);
		auto rhs = ret_;

		emit(assem::move("mov `s0, `(d0)", {lhs}, {rhs}));
		return;
	}

	mv.lhs()->accept(*this);
	auto lhs = ret_;
	mv.rhs()->accept(*this);
	auto rhs = ret_;

	emit(assem::move("mov `s0, `d0", {lhs}, {rhs}));
}

void generator::visit_mem(tree::mem &mm)
{
	mm.e()->accept(*this);
	::temp::temp dst;
	emit(assem::move("mov (`s0), `d0", {dst}, {ret_}));
	ret_ = dst;
}

void generator::visit_cnst(tree::cnst &c)
{
	::temp::temp dst;
	std::string instr("mov $");
	instr += std::to_string(c.value_);
	instr += ", `d0";

	emit(assem::oper(instr, {dst}, {}, {}));

	ret_ = dst;
}

void generator::visit_temp(tree::temp &t) { ret_ = t.temp_; }

void generator::visit_binop(tree::binop &b)
{
	b.lhs()->accept(*this);
	auto lhs = ret_;
	b.rhs()->accept(*this);
	auto rhs = ret_;

	::temp::temp dst;

	emit(assem::move("mov `s0, `d0", {dst}, {rhs}));
	if (b.op_ == ops::binop::PLUS)
		emit(assem::oper("add `s0, `d0", {dst}, {lhs}, {}));
	else if (b.op_ == ops::binop::MINUS)
		emit(assem::oper("sub `s0, `d0", {dst}, {lhs}, {}));

	ret_ = dst;
}

void generator::emit(const assem::instr &ins)
{
	unsigned width = 30;
	std::cout << ins.repr_;
	for (unsigned i = 0; i < width - ins.repr_.size(); i++)
		std::cout << ' ';
	std::cout << ins.to_string() << '\n';

	instrs_.push_back(ins);
}
} // namespace mach
