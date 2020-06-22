#include "amd64-common.hh"

namespace mach::amd64
{
struct reg {
	utils::temp label;
	std::array<std::string, 4> repr;
};

reg register_array[] = {
	{make_unique("rax"), {"%rax", "%eax", "%ax", "%al"}},
	{make_unique("rbx"), {"%rbx", "%ebx", "%bx", "%bl"}},
	{make_unique("rcx"), {"%rcx", "%ecx", "%cx", "%cl"}},
	{make_unique("rdx"), {"%rdx", "%edx", "%dx", "%dl"}},
	{make_unique("rsi"), {"%rsi", "%esi", "%si", "%sil"}},
	{make_unique("rdi"), {"%rdi", "%edi", "%di", "%dil"}},
	{make_unique("rsp"), {"%rsp", "%esp", "%sp", "%spl"}},
	{make_unique("rbp"), {"%rbp", "%ebp", "%bp", "%bpl"}},
	{make_unique("r8"), {"%r8", "%r8d", "%r8w", "%r8b"}},
	{make_unique("r9"), {"%r9", "%r9d", "%r9w", "%r9b"}},
	{make_unique("r10"), {"%r10", "%r10d", "%r10w", "%r10b"}},
	{make_unique("r11"), {"%r11", "%r11d", "%r11w", "%r11b"}},
	{make_unique("r12"), {"%r12", "%r12d", "%r12w", "%r12b"}},
	{make_unique("r13"), {"%r13", "%r13d", "%r13w", "%r13b"}},
	{make_unique("r14"), {"%r14", "%r14d", "%r14w", "%r14b"}},
	{make_unique("r15"), {"%r15", "%r15d", "%r15w", "%r15b"}},
};

utils::temp_set registers()
{
	return utils::temp_set(caller_saved_regs())
	       + utils::temp_set(callee_saved_regs())
	       + utils::temp_set(args_regs());
}

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
		reg_to_temp(regs::R15),
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
		reg_to_temp(regs::RBP),
	};
}

utils::temp fp() { return register_array[regs::RBP].label; }

utils::temp rv() { return register_array[regs::RAX].label; }

std::unordered_map<utils::temp, std::string> temp_map()
{
	std::unordered_map<utils::temp, std::string> ret;
	for (unsigned i = 0; i < 16; i++)
		ret.insert(
			{register_array[i].label, register_array[i].repr[0]});
	return ret;
}

std::string register_repr(utils::temp t, unsigned size)
{
	unsigned size_offt = 0;
	if (size == 4)
		size_offt = 1;
	else if (size == 2)
		size_offt = 2;
	else if (size == 1)
		size_offt = 3;

	for (unsigned i = 0; i < 16; i++) {
		if (register_array[i].label == t)
			return register_array[i].repr[size_offt];
	}

	UNREACHABLE("register not found");
}

utils::temp repr_to_register(std::string repr)
{
	for (size_t i = 0; i < 16; i++) {
		for (size_t j = 0; j < 4; j++) {
			if (register_array[i].repr[j] == repr)
				return register_array[i].label;
		}
	}

	UNREACHABLE("Register does not exist");
}

utils::ref<types::ty> gpr_type() { return types::integer_type(); }

utils::temp reg_to_temp(regs r) { return register_array[r].label; }
utils::temp reg_to_str(regs r) { return register_array[r].repr[0]; }
} // namespace mach::amd64
