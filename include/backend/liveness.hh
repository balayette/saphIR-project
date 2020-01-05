#pragma once

#include <utility>
#include <unordered_map>
#include "utils/graph.hh"
#include "utils/temp.hh"
#include "backend/cfg.hh"

namespace backend
{
struct ifence_node {
	ifence_node(const utils::temp &t);
	bool operator==(const ifence_node &rhs) const;
	utils::temp value_;
};

std::ostream &operator<<(std::ostream &os, const ifence_node &n);

class ifence_graph
{
      public:
	using node_type = utils::gnode<ifence_node>;

	ifence_graph(utils::graph<cfgnode> &cfg);
	utils::graph<ifence_node> graph_;

	std::unordered_map<utils::temp, utils::node_id> tnodes_;
	std::unordered_map<utils::temp, utils::temp_pair_set> move_list_;
	utils::temp_pair_set worklist_moves_;
};
} // namespace backend
