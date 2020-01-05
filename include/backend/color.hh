#pragma once

#include <unordered_map>
#include "utils/uset.hh"
#include <vector>
#include "utils/temp.hh"
#include "backend/liveness.hh"

namespace backend
{
namespace regalloc
{
struct coloring_out {
	utils::temp_endomap allocation;
	std::vector<utils::temp> spills;
	utils::temp_set colored;
	utils::temp_set coalesced;
};

coloring_out color(backend::ifence_graph &ifence,
		   utils::temp_set initial);
} // namespace regalloc
} // namespace backend

