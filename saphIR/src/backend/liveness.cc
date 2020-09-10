#include "backend/liveness.hh"
#include "utils/uset.hh"
#include "backend/dataflow.hh"
#include "utils/assert.hh"
#include <algorithm>

namespace backend
{
ifence_node::ifence_node(const assem::temp &t) : value_(t) {}

bool ifence_node::operator==(const ifence_node &rhs) const
{
	return value_ == rhs.value_;
}

std::ostream &operator<<(std::ostream &os, const ifence_node &n)
{
	return os << "[label=\"" << n.value_ << "\"]";
}

ifence_graph::ifence_graph(const utils::graph<cfgnode> &cfg)
{
        auto [in, out] = dataflow_analysis(cfg);

	for (utils::node_id n = 0; n < cfg.size(); n++) {
		auto *node = cfg.get(n);
		if (node->is_move) {
			ASSERT(node->def.size() <= 1, "defs in move > 1");
			ASSERT(node->use.size() <= 2, "Too many uses");
			auto use = node->use.begin();

			for (auto def = node->def.begin();
			     def != node->def.end(); def++) {
				utils::node_id defn =
					graph_.get_or_insert(*def);
				tnodes_[*def] = defn;
				for (auto b : out[n]) {
					if (node->use.find(b)
					    != node->use.end())
						continue;

					utils::node_id outn =
						graph_.get_or_insert(b);

					graph_.add_edge(defn, outn);
				}

				if (use != node->use.end()) {
					worklist_moves_.insert({*def, *use});
					for (auto &t : node->def + node->use) {
						auto [it, _] =
							move_list_.insert(
								{t, {}});
						it->second += {*def, *use};
					}
				}
			}
		} else {
			for (auto def : node->def) {
				utils::node_id defn = graph_.get_or_insert(def);
				for (auto b : out[n]) {
					utils::node_id outn =
						graph_.get_or_insert(b);
					graph_.add_edge(defn, outn);
				}
			}
		}
	}
}
} // namespace backend
