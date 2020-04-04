#include "backend/cfg.hh"
#include <fstream>

namespace backend
{
cfgnode::cfgnode(assem::temp_set def, assem::temp_set use, bool is_move)
    : def(def), use(use), is_move(is_move)
{
}

std::ostream &operator<<(std::ostream &os, const cfgnode &node)
{
	os << "[label=\"";
	os << node.debug << " ";
	os << "defs:";
	for (auto d : node.def)
		os << " " << d;
	os << " uses:";
	for (auto u : node.use)
		os << " " << u;
	os << "\"";
	if (node.is_move)
		os << ", style=filled, fillcolor=\"gray\"";
	return os << "]";
}

cfg::cfg(std::vector<assem::rinstr> instrs, utils::label prologue)
    : instrs_(instrs)
{
	for (unsigned i = 0; i < instrs_.size(); i++) {
		if (auto lbl = instrs_[i].as<assem::label>())
			label_to_node_.insert({lbl->lab_, i});
	}

	build(label_to_node_[prologue], std::nullopt);
}

void cfg::build(unsigned idx, std::optional<utils::node_id> pred)
{
	if (visited_.count(idx)) {
		if (pred != std::nullopt)
			cfg_.add_edge(*pred, visited_[idx]);
		return;
	}

	assem::temp_set def(instrs_[idx]->dst_);
	assem::temp_set use(instrs_[idx]->src_);
	bool is_move = instrs_[idx].as<assem::move>() != nullptr;

	cfgnode nn(def, use, is_move);
	nn.debug = instrs_[idx]->to_string();
	utils::node_id n = cfg_.add_node(nn);
	visited_.insert({idx, n});

	if (pred != std::nullopt)
		cfg_.add_edge(*pred, n);

	for (auto lbl : instrs_[idx]->jmps_) {
		// A jump destination might not exist (done label)
		if (label_to_node_.count(lbl))
			build(label_to_node_[lbl], n);
	}

	// Don't fallthru on jumps, because even cjumps list all their
	// possible destinations in jmps_ (!= Appel's implem)
	if (instrs_[idx]->jmps_.size() > 0)
		return;

	if (idx + 1 < instrs_.size())
		build(idx + 1, n);
}
} // namespace backend
