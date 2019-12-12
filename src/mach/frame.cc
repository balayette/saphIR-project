#include "mach/frame.hh"

#include <array>

namespace frame
{
enum regs {
	RAX,
	RBX,
	RCX,
	RDX,
	RSI,
	RDI,
	RSP,
	RBP,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15
};

std::array<::temp::temp, 16> reg_to_temp{
	make_unique("rax").get(), make_unique("rbx").get(),
	make_unique("rcx").get(), make_unique("rdx").get(),
	make_unique("rsi").get(), make_unique("rdi").get(),
	make_unique("rsp").get(), make_unique("rbp").get(),
	make_unique("r8").get(),  make_unique("r9").get(),
	make_unique("r10").get(), make_unique("r11").get(),
	make_unique("r12").get(), make_unique("r13").get(),
	make_unique("r14").get(), make_unique("r15").get(),
};

std::array<std::string, 16> reg_to_str{
	"%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rsp", "%rbp",
	"%r8",	"%r9",	"%r10", "%r11", "%r12", "%r13", "%r14", "%r15"};

const ::temp::temp &fp() { return reg_to_temp[regs::RBP]; }

const ::temp::temp &rv() { return reg_to_temp[regs::RAX]; }

std::ostream &operator<<(std::ostream &os, const access &a)
{
	return a.print(os);
}

std::ostream &operator<<(std::ostream &os, const frame &f)
{
	for (auto a : f.formals_)
		os << a << '\n';
	return os;
}

in_reg::in_reg(::temp::temp reg) : reg_(reg) {}

ir::tree::rexp in_reg::exp() const { return new ir::tree::temp(reg_); }

std::ostream &in_reg::print(std::ostream &os) const
{
	return os << "in_reg(" << reg_ << ")";
}

in_frame::in_frame(int offt) : offt_(offt) {}

ir::tree::rexp in_frame::exp() const
{
	return new ir::tree::mem(
		new ir::tree::binop(ops::binop::PLUS, new ir::tree::temp(fp()),
				    new ir::tree::cnst(offt_)));
}

std::ostream &in_frame::print(std::ostream &os) const
{
	os << "in_frame(" << fp() << " ";
	if (offt_ < 0)
		os << "- " << -offt_;
	else
		os << "+ " << offt_;
	return os << ")";
}

frame::frame(const symbol &s, const std::vector<bool> &args)
    : s_(s), escaping_count_(0), reg_count_(0)
{
	/*
	 * This struct contains a view of where the args should be when
	 * inside the function. The translation for escaping arguments
	 * passed in registers will be done at a later stage.
	 */
	for (size_t i = 0; i < args.size() && i <= 5; i++) {
		formals_.push_back(alloc_local(args[i]));
	}
	for (size_t i = 6; i < args.size(); i++) {
		formals_.push_back(new in_frame((i - 6) * 8 + 16));
	}
}

utils::ref<access> frame::alloc_local(bool escapes)
{
	if (escapes)
		return new in_frame(-(escaping_count_++ * 8 + 8));
	reg_count_++;
	return new in_reg(temp::temp());
}

ir::tree::rstm frame::proc_entry_exit_1(ir::tree::rstm s, ::temp::label ret_lbl)
{
	// Placeholder for the epilogue
	return new ir::tree::seq({s, new ir::tree::label(ret_lbl)});
}
} // namespace frame
