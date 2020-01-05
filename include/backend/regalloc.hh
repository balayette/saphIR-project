#pragma once

#include <vector>
#include "mach/frame.hh"
#include "ass/instr.hh"
#include "backend/liveness.hh"
#include "backend/cfg.hh"

namespace backend
{
namespace regalloc
{
void alloc(std::vector<assem::rinstr> &instrs, mach::fun_fragment &f);

void rewrite(std::vector<assem::rinstr> &instrs,
				 std::vector<utils::temp> spills,
				 mach::frame &f);
} // namespace regalloc
} // namespace backend