#pragma once

#include <vector>
#include "utils/temp.hh"
#include "ir/types.hh"

namespace mach::aarch64
{
enum regs {
	R0 = 0,
	R1,
	R2,
	R3,
	R4,
	R5,
	R6,
	R7,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	R16,
	R17,
	R18,
	R19,
	R20,
	R21,
	R22,
	R23,
	R24,
	R25,
	R26,
	R27,
	R28,
	FP,
	LR,
	SP,
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
} // namespace mach::aarch64
