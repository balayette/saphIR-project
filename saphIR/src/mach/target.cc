#include "mach/target.hh"

namespace mach
{
static utils::ref<mach::target> curr_target;

std::string target::asm_string(utils::label lab, const std::string &str)
{
	std::string ret(lab.get() + ":\n\t.string \"" + str + "\"\n");
	return ret;
}

size_t target::reg_count() { return registers().size(); }

utils::ref<types::ty> target::invalid_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::INVALID, types::signedness::INVALID, *this);
}

utils::ref<types::ty> target::void_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::VOID, types::signedness::INVALID, *this);
}

utils::ref<types::ty> target::string_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::STRING, types::signedness::INVALID, *this);
}

frame::frame(target &target, const symbol &s, bool has_return)
    : target_(target), s_(s), leaf_(true), has_return_(has_return)
{
}

asm_function::asm_function(const std::string &prologue,
			   const std::vector<assem::rinstr> &instrs,
			   const std::string &epilogue)
    : prologue_(prologue), instrs_(instrs), epilogue_(epilogue)
{
}

#define F(Node, ...) return new ir::tree::Node(*this, __VA_ARGS__)

ir::tree::cnst *target::make_cnst(uint64_t value) { F(cnst, value); }

ir::tree::braceinit *
target::make_braceinit(utils::ref<types::ty> &ty,
		       const std::vector<ir::tree::rexp> &exps)
{
	F(braceinit, ty, exps);
}
ir::tree::name *target::make_name(const utils::label &label) { F(name, label); }
ir::tree::name *target::make_name(const utils::label &label,
				  utils::ref<types::ty> ty)
{
	F(name, label, ty);
}
ir::tree::temp *target::make_temp(const utils::temp &temp,
				  utils::ref<types::ty> ty)
{
	F(temp, temp, ty);
}
ir::tree::binop *target::make_binop(ops::binop op, ir::tree::rexp lhs,
				    ir::tree::rexp rhs,
				    utils::ref<types::ty> ty)
{
	F(binop, op, lhs, rhs, ty);
}
ir::tree::unaryop *target::make_unaryop(ops::unaryop op, ir::tree::rexp e,
					utils::ref<types::ty> type)
{
	F(unaryop, op, e, type);
}
ir::tree::mem *target::make_mem(ir::tree::rexp e) { F(mem, e); }
ir::tree::call *target::make_call(const ir::tree::rexp &f,
				  const std::vector<ir::tree::rexp> &args,
				  utils::ref<types::ty> type)
{
	F(call, f, args, type);
}
ir::tree::eseq *target::make_eseq(ir::tree::rstm lhs, ir::tree::rexp rhs)
{
	F(eseq, lhs, rhs);
}
ir::tree::move *target::make_move(ir::tree::rexp lhs, ir::tree::rexp rhs)
{
	F(move, lhs, rhs);
}
ir::tree::sexp *target::make_sexp(ir::tree::rexp e) { F(sexp, e); }
ir::tree::jump *target::make_jump(ir::tree::rexp dest,
				  const std::vector<utils::label> &avlbl_dests)
{
	F(jump, dest, avlbl_dests);
}
ir::tree::cjump *target::make_cjump(ops::cmpop op, ir::tree::rexp lhs,
				    ir::tree::rexp rhs,
				    const utils::label &ltrue,
				    const utils::label &lfalse)
{
	F(cjump, op, lhs, rhs, ltrue, lfalse);
}
ir::tree::seq *target::make_seq(const std::vector<ir::tree::rstm> &body)
{
	F(seq, body);
}
ir::tree::label *target::make_label(const utils::label &name)
{
	F(label, name);
}
ir::tree::asm_block *
target::make_asm_block(const std::vector<std::string> &lines,
		       const std::vector<utils::temp> &reg_in,
		       const std::vector<utils::temp> &reg_out,
		       const std::vector<utils::temp> &reg_clob)
{
	F(asm_block, lines, reg_in, reg_out, reg_clob);
}

#undef F
} // namespace mach
