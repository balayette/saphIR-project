#include "mach/frame.hh"
#include "utils/assert.hh"
#include "ir/canon/bb.hh"

#include <array>

#define ROUND_UP(x, m) (((x) + (m)-1) & ~((m)-1))

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

utils::temp_set registers()
{
	return utils::temp_set(caller_saved_regs())
	       + utils::temp_set(callee_saved_regs())
	       + utils::temp_set(args_regs());
}

std::unordered_map<utils::temp, std::string> temp_map()
{
	std::unordered_map<utils::temp, std::string> ret;
	for (unsigned i = 0; i < reg_temp.size(); i++)
		ret.insert({reg_temp[i], reg_str[i]});
	return ret;
} // namespace mach

utils::temp fp() { return reg_temp[regs::RBP]; }

utils::temp rv() { return reg_temp[regs::RAX]; }

unsigned reg_count() { return registers().size(); }

std::vector<utils::temp> caller_saved_regs()
{
	return {
		reg_to_temp(regs::R10),
		reg_to_temp(regs::R11),
		reg_to_temp(regs::RAX),
	};
}

std::vector<utils::temp> callee_saved_regs()
{
	return {
		reg_to_temp(regs::RBX), reg_to_temp(regs::R12),
		reg_to_temp(regs::R13), reg_to_temp(regs::R14),
		reg_to_temp(regs::R15), reg_to_temp(regs::RBP),
	};
}

std::vector<utils::temp> args_regs()
{
	return {
		reg_to_temp(regs::RDI), reg_to_temp(regs::RSI),
		reg_to_temp(regs::RDX), reg_to_temp(regs::RCX),
		reg_to_temp(regs::R8),	reg_to_temp(regs::R9),
	};
}

std::vector<utils::temp> special_regs()
{
	return {
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

global_acc::global_acc(const symbol &name) : name_(name) {}
ir::tree::rexp global_acc::exp() const
{
	return new ir::tree::mem(new ir::tree::name(name_.get()));
}
std::ostream &global_acc::print(std::ostream &os) const
{
	return os << "global_acc(" << name_ << ")";
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
	auto in_regs = args_regs();
	auto *seq = new ir::tree::seq({});

	auto callee_saved = callee_saved_regs();
	std::vector<utils::temp> callee_saved_temps(callee_saved.size());
	for (size_t i = 0; i < callee_saved.size(); i++)
		seq->children_.push_back(new ir::tree::move(
			new ir::tree::temp(callee_saved_temps[i]),
			new ir::tree::temp(callee_saved[i])));

	for (size_t i = 0; i < formals_.size() && i < in_regs.size(); i++) {
		seq->children_.push_back(new ir::tree::move(
			formals_[i]->exp(), new ir::tree::temp(in_regs[i])));
	}

	seq->children_.push_back(s);

	auto *ret = new ir::tree::label(ret_lbl);
	seq->children_.push_back(ret);

	for (size_t i = 0; i < callee_saved.size(); i++) {
		seq->children_.push_back(new ir::tree::move(
			new ir::tree::temp(callee_saved[i]),
			new ir::tree::temp(callee_saved_temps[i])));
	}

	return seq;
}

void frame::proc_entry_exit_2(std::vector<assem::rinstr> &instrs)
{
	std::vector<utils::temp> live(special_regs());
	for (auto &r : callee_saved_regs())
		live.push_back(r);
	instrs.push_back(new assem::oper("", {}, live, {}));
}

std::string asm_string(utils::label lab, const std::string &str)
{
	std::string ret(".L_" + lab.get() + ":\n\t.string \"" + str + "\"\n");
	return ret;
}

asm_function frame::proc_entry_exit_3(std::vector<assem::rinstr> &instrs,
				      utils::label pro_lbl,
				      utils::label epi_lbl)
{
	std::string prologue(".global ");
	prologue += s_.get() + '\n' + s_.get() + ":\n";
	prologue +=
		"\tpush %rbp\n"
		"\tmov %rsp, %rbp\n";
	if (escaping_count_ != 0) {
		prologue += "\tsub $";
		prologue += std::to_string(ROUND_UP(escaping_count_ * 8, 16));
		prologue += ", %rsp\n";
	}
	prologue += "\tjmp .L_" + pro_lbl.get() + '\n';

	std::string epilogue(".L_" + epi_lbl.get());
	epilogue +=
		":\n"
		"\tleave\n"
		"\tret\n";

	return asm_function(prologue, instrs, epilogue);
}

asm_function::asm_function(const std::string &prologue,
			   const std::vector<assem::rinstr> &instrs,
			   const std::string &epilogue)
    : prologue_(prologue), instrs_(instrs), epilogue_(epilogue)
{
}
} // namespace mach
