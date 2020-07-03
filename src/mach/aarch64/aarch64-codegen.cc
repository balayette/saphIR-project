#include "mach/aarch64/aarch64-instr.hh"
#include "mach/aarch64/aarch64-codegen.hh"
#include "aarch64-common.hh"
#include "utils/assert.hh"
#include "utils/misc.hh"

#include <sstream>

using namespace ir;
using namespace assem;
using namespace assem::aarch64;

namespace mach::aarch64
{
assem::temp aarch64_generator::codegen(ir::tree::rnode instr)
{
	instr->accept(g_);
	return g_.ret_;
}

void aarch64_generator::codegen(ir::tree::rnodevec instrs)
{
	for (auto &i : instrs)
		i->accept(g_);
}

void aarch64_generator::emit(assem::rinstr &i) { g_.emit(i); }

std::vector<assem::rinstr> aarch64_generator::output() { return g_.instrs_; }

/*
 * The generator heavily relies on the register allocator to remove redundant
 * moves, and makes little effort to limit the temporary use.
 */

#define EMIT(x)                                                                \
	do {                                                                   \
		emit(new x);                                                   \
	} while (0)

assem::temp reg_to_assem_temp(regs t) { return reg_to_temp(t); }
assem::temp
reg_to_assem_temp(regs t, unsigned sz,
		  types::signedness is_signed = types::signedness::SIGNED)
{
	auto tmp = reg_to_assem_temp(t);
	tmp.size_ = sz;
	tmp.is_signed_ = is_signed;
	return tmp;
}

std::string label_to_asm(const utils::label &lbl)
{
	std::string ret(".L_");
	ret += lbl;

	return ret;
}

void generator::visit_label(tree::label &l)
{
	EMIT(assem::label(label_to_asm(l.name_) + std::string(":"), l.name_));
}

void generator::visit_cnst(tree::cnst &c)
{
	assem::temp dst;

	std::string repr("mov `d0, #" + std::to_string(c.value_));
	EMIT(oper(repr, {dst}, {}, {}));

	ret_ = dst;
}

void generator::visit_jump(tree::jump &j)
{
	if (auto dest = j.dest().as<tree::name>()) {
		std::string repr("b ");
		repr += label_to_asm(dest->label_);

		EMIT(oper(repr, {}, {}, {dest->label_}));
	} else
		UNREACHABLE("Destination of jump must be a name");
}

void generator::visit_name(tree::name &n)
{
	assem::temp ret;
	EMIT(oper("ldr `d0, =" + std::string(n.label_), {ret}, {}, {}));

	ret_ = ret;
}

void generator::visit_move(tree::move &mv)
{
	auto signedness = mv.lhs()->ty_->get_signedness();

	if (auto lmem = mv.lhs().as<tree::mem>()) {
		lmem->e()->accept(*this);
		auto lhs = ret_;
		mv.rhs()->accept(*this);
		auto rhs = assem::temp(ret_, mv.lhs()->assem_size());

		EMIT(store(lhs, rhs, mv.lhs()->assem_size()));
		return;
	}

	mv.lhs()->accept(*this);
	auto lhs = assem::temp(ret_, mv.lhs()->assem_size(), signedness);
	mv.rhs()->accept(*this);
	auto rhs = assem::temp(ret_, mv.rhs()->assem_size(), signedness);

	EMIT(simple_move(lhs, rhs));
}

void generator::visit_temp(tree::temp &t)
{
	ret_ = assem::temp(t.temp_, t.assem_size(), t.ty_->get_signedness());
}

void generator::visit_mem(tree::mem &mm)
{
	assem::temp dst(mm.ty_->assem_size());

	mm.e()->accept(*this);
	EMIT(load(dst, ret_, mm.ty_->assem_size()));

	ret_ = dst;
}

void generator::visit_call(tree::call &c)
{
	std::vector<assem::temp> src;
	auto cc = args_regs();
	auto args = c.args();
	size_t reg_args_count = std::min(args.size(), cc.size());

	ASSERT(args.size() < 8, "Too many params");

	for (size_t i = 0; i < reg_args_count; i++) {
		args[i]->accept(*this);
		src.push_back(cc[i]);

		EMIT(simple_move(assem::temp(cc[i], std::max(ret_.size_, 4u),
					     ret_.is_signed_),
				 ret_));
	}

	auto clobbered_regs = caller_saved_regs();
	std::vector<assem::temp> clobbered;
	clobbered.insert(clobbered.end(), clobbered_regs.begin(),
			 clobbered_regs.end());
	clobbered.insert(clobbered.end(), cc.begin(), cc.end());

	std::string repr;
	if (auto name = c.f().as<tree::name>()) {
		repr = "bl " + name->label_.get();
	} else {
		repr = "br `s0";
		c.f()->accept(*this);
		src.insert(src.begin(), ret_);
	}

	EMIT(oper(repr, clobbered, src, {}));

	assem::temp ret(c.ty_->assem_size());
	if (ret.size_ != 0)
		EMIT(simple_move(ret, reg_to_assem_temp(regs::R0)));

	ret_ = ret;
}

void generator::visit_cjump(tree::cjump &cj)
{
	cj.lhs()->accept(*this);
	auto lhs = ret_;
	cj.rhs()->accept(*this);
	auto rhs = ret_;

	assem::temp cmpr(8, lhs.is_signed_);
	assem::temp cmpl(8, rhs.is_signed_);

	EMIT(simple_move(cmpr, rhs));
	EMIT(simple_move(cmpl, lhs));

	EMIT(oper("cmp `s0, `s1", {}, {cmpl, cmpr}, {}));
	std::string repr("b.");
	if (cj.op_ == ops::cmpop::EQ)
		repr += "eq ";
	else if (cj.op_ == ops::cmpop::NEQ)
		repr += "ne ";
	else if (cj.op_ == ops::cmpop::SMLR)
		repr += "lt ";
	else if (cj.op_ == ops::cmpop::GRTR)
		repr += "gt ";
	else if (cj.op_ == ops::cmpop::SMLR_EQ)
		repr += "le ";
	else if (cj.op_ == ops::cmpop::GRTR_EQ)
		repr += "ge ";
	else
		UNREACHABLE("Impossible cmpop");

	repr += label_to_asm(cj.ltrue_);
	EMIT(oper(repr, {}, {}, {cj.ltrue_, cj.lfalse_}));
}

void generator::visit_binop(tree::binop &b)
{
	auto oper_sz = std::max(b.lhs()->assem_size(), b.rhs()->assem_size());
	oper_sz = std::max(oper_sz, 4ul);

	b.lhs()->accept(*this);
	auto lhs = assem::temp(oper_sz);
	EMIT(simple_move(lhs, ret_));

	b.rhs()->accept(*this);
	auto rhs = assem::temp(oper_sz);
	EMIT(simple_move(rhs, ret_));

	assem::temp dst(oper_sz);

	if (b.op_ == ops::binop::PLUS)
		EMIT(oper("add `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::MINUS)
		EMIT(oper("sub `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::MULT)
		EMIT(oper("mul `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::DIV || b.op_ == ops::binop::MOD) {
		EMIT(oper("sdiv `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
		if (b.op_ == ops::binop::MOD)
			EMIT(oper("msub `d0, `s0, `s1, `s2", {dst},
				  {dst, rhs, lhs}, {}));
	} else if (b.op_ == ops::binop::BITXOR)
		EMIT(oper("eor `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::BITOR)
		EMIT(oper("orr `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::BITAND)
		EMIT(oper("and `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::BITLSHIFT)
		EMIT(oper("lsl `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::BITRSHIFT)
		EMIT(oper("lsr `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else if (b.op_ == ops::binop::ARITHBITRSHIFT)
		EMIT(oper("asr `d0, `s0, `s1", {dst}, {lhs, rhs}, {}));
	else
		UNREACHABLE("Unimplemented binop");

	ret_ = dst;
}

void generator::visit_unaryop(tree::unaryop &b)
{
	b.e()->accept(*this);
	auto val = ret_;

	if (b.op_ == ops::unaryop::NOT) {
		assem::temp dst(8, types::signedness::UNSIGNED);
		EMIT(oper("mov `d0, #0", {dst}, {}, {}));
		EMIT(oper("cmp `s0, #0", {}, {val}, {}));
		dst.size_ = 1;
		EMIT(oper("cset `d0, EQ", {dst}, {}, {}));
		ret_ = dst;
	} else if (b.op_ == ops::unaryop::NEG) {
		assem::temp dst(b.ty_->size(), val.is_signed_);
		EMIT(oper("negs `d0, `s0", {dst}, {val}, {}));
		ret_ = dst;
	} else if (b.op_ == ops::unaryop::BITNOT) {
		assem::temp dst(b.ty_->size(), val.is_signed_);
		EMIT(oper("mvn `d0, `s0", {dst}, {val}, {}));
		ret_ = dst;
	} else
		UNREACHABLE("Unimplemented binary op\n");
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
} // namespace mach::aarch64
