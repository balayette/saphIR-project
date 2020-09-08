#include "backend/dataflow.hh"

namespace backend
{
dataflow_result dataflow_analysis(utils::graph<cfgnode> &cfg)
{
	std::vector<assem::temp_set> in(cfg.size());
	std::vector<assem::temp_set> out(cfg.size());

	utils::uset<utils::node_id> worklist;
	for (utils::node_id n = 0; n < cfg.size(); n++) {
		auto *node = cfg.get(n);
		in[n] = node->use;
		worklist += n;
	}

	while (worklist.size()) {
		auto n = worklist.pop();

		assem::temp_set children_in;
		auto succs = cfg.nodes_[n].succ_;
		for (auto s : succs)
			children_in += in[s];

		out[n] = children_in;
		auto old_in = in[n];

		auto *node = cfg.get(n);
		in[n] = node->use + (out[n] - node->def);

		if (in[n] != old_in) {
			auto preds = cfg.nodes_[n].pred_;
			worklist += std::make_pair(preds.begin(), preds.end());
		}
	}

	return std::make_pair(in, out);
}
} // namespace backend
