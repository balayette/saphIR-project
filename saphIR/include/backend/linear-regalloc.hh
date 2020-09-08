#pragma once

#include <utility>
#include "utils/temp.hh"
#include "ass/instr.hh"
#include "backend/cfg.hh"
#include "utils/graph.hh"
#include "mach/target.hh"

namespace backend
{
std::pair<std::vector<assem::temp_set>, std::vector<assem::temp_set>>
dataflow(utils::graph<cfgnode> &cfg);

void linear_alloc(std::vector<assem::rinstr> &instrs, mach::fun_fragment &f);
} // namespace backend
