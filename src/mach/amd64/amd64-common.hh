#pragma once

#include <vector>
#include "utils/temp.hh"
#include "frontend/types.hh"

namespace mach::amd64
{
enum regs {
	RAX = 0,
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

utils::temp_set registers();
std::vector<utils::temp> caller_saved_regs();
std::vector<utils::temp> callee_saved_regs();
std::vector<utils::temp> args_regs();
std::vector<utils::temp> special_regs();
utils::temp fp();
utils::temp rv();

std::unordered_map<utils::temp, std::string> temp_map();
std::string register_repr(utils::temp t, unsigned size);
utils::temp repr_to_register(std::string repr);

utils::temp reg_to_temp(regs r);
utils::temp reg_to_str(regs r);
} // namespace mach::amd64
