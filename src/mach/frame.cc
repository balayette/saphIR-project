#include "mach/frame.hh"

#include <array>

namespace mach
{
std::array<utils::temp, 16> reg_temp{
	make_unique("rax").get(), make_unique("rbx").get(),
	make_unique("rcx").get(), make_unique("rdx").get(),
	make_unique("rsi").get(), make_unique("rdi").get(),
	make_unique("rsp").get(), make_unique("rbp").get(),
	make_unique("r8").get(),  make_unique("r9").get(),
	make_unique("r10").get(), make_unique("r11").get(),
	make_unique("r12").get(), make_unique("r13").get(),
	make_unique("r14").get(), make_unique("r15").get(),
};

std::array<std::string, 16> reg_str{
	"%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rsp", "%rbp",
	"%r8",	"%r9",	"%r10", "%r11", "%r12", "%r13", "%r14", "%r15"};

utils::temp reg_to_temp(regs r) { return reg_temp[r]; }

utils::temp reg_to_str(regs r) { return reg_str[r]; }

utils::temp fp() { return reg_temp[regs::RBP]; }

utils::temp rv() { return reg_temp[regs::RAX]; }

std::vector<utils::temp> caller_saved_regs()
{
	return {
		reg_to_temp(regs::RAX),
		reg_to_temp(regs::R11),
	};
}

std::vector<utils::temp> callee_saved_regs()
{
	return {
		reg_to_temp(regs::RBX), reg_to_temp(regs::R12),
		reg_to_temp(regs::R13), reg_to_temp(regs::R14),
		reg_to_temp(regs::R15),
	};
}

std::vector<utils::temp> args_regs()
{
	return {
		reg_to_temp(regs::RDI), reg_to_temp(regs::RSI),
		reg_to_temp(regs::RDX), reg_to_temp(regs::RCX),
		reg_to_temp(regs::R8),	reg_to_temp(regs::R9),
		reg_to_temp(regs::R10),
	};
}

std::vector<utils::temp> special_regs()
{
	return {
		reg_to_temp(regs::RBP),
		reg_to_temp(regs::RSP),
	};
}

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

in_reg::in_reg(utils::temp reg) : reg_(reg) {}

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
	return new in_reg(utils::temp());
}

ir::tree::rstm frame::proc_entry_exit_1(ir::tree::rstm s, utils::label ret_lbl)
{
	// Placeholder for the epilogue
	return new ir::tree::seq({s, new ir::tree::label(ret_lbl)});
}

void frame::proc_entry_exit_2(std::vector<assem::rinstr> &instrs)
{
	instrs.push_back(new assem::oper("", {}, special_regs(), {}));
}

void frame::proc_entry_exit_3(std::vector<assem::rinstr> &instrs)
{
	(void)instrs;
}
} // namespace mach
