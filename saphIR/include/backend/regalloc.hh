#pragma once

#include "ass/instr.hh"
#include "mach/target.hh"

namespace backend::regalloc
{
void rewrite(std::vector<assem::rinstr> &instrs,
	     std::vector<assem::temp> spills, mach::frame &f);

void replace_allocations(std::vector<assem::rinstr> &instrs,
			const assem::temp_endomap &allocation);
} // namespace backend::regalloc
