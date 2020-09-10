#pragma once

#include <utility>
#include <unordered_map>
#include "utils/graph.hh"
#include "utils/temp.hh"
#include "ass/instr.hh"
#include "backend/cfg.hh"

namespace backend
{
struct ifence_node {
	ifence_node(const assem::temp &t);
	bool operator==(const ifence_node &rhs) const;
	assem::temp value_;
};

std::ostream &operator<<(std::ostream &os, const ifence_node &n);

class ifence_graph
{
      public:
	using node_type = utils::gnode<ifence_node>;

	ifence_graph(const utils::graph<cfgnode> &cfg);
	utils::graph<ifence_node> graph_;

	std::unordered_map<assem::temp, utils::node_id> tnodes_;
	std::unordered_map<assem::temp, assem::temp_pair_set> move_list_;
	assem::temp_pair_set worklist_moves_;
};
} // namespace backend
