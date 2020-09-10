#include <utility>
#include <vector>

#include "ass/instr.hh"
#include "backend/cfg.hh"

namespace backend
{
using dataflow_result =
	std::pair<std::vector<assem::temp_set>, std::vector<assem::temp_set>>;

dataflow_result dataflow_analysis(const utils::graph<cfgnode> &cfg);
} // namespace backend
