#pragma once

#include <unordered_map>
#include "utils/uset.hh"
#include "mach/target.hh"
#include <vector>
#include "utils/temp.hh"
#include "backend/liveness.hh"
#include "ass/instr.hh"

namespace backend
{
namespace regalloc
{
struct coloring_out {
	assem::temp_endomap allocation;
	std::vector<assem::temp> spills;
	assem::temp_set colored;
	assem::temp_set coalesced;
};

coloring_out color(mach::target& target, backend::ifence_graph &ifence, assem::temp_set initial);
} // namespace regalloc
} // namespace backend

