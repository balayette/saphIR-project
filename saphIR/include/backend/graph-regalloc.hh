#pragma once

#include <vector>
#include "mach/target.hh"
#include "ass/instr.hh"
#include "backend/liveness.hh"
#include "backend/cfg.hh"
#include "backend/regalloc.hh"

namespace backend::regalloc
{
void graph_alloc(std::vector<assem::rinstr> &instrs, mach::fun_fragment &f);
} // namespace backend::regalloc
