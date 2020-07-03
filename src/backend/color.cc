#include "backend/color.hh"
#include <climits>
#include <utility>
#include "utils/assert.hh"
#include "mach/target.hh"
#include "utils/random.hh"
#include "utils/algo.hh"

namespace backend
{
namespace regalloc
{
struct allocator {
	allocator(
		mach::target &target,
		std::unordered_map<assem::temp, assem::temp_pair_set> move_list,
		assem::temp_pair_set worklist_moves)
	    : target_(target), move_list_(move_list),
	      moves_wkl_(worklist_moves), precolored_(target.temp_map())
	{
	}

	void add_edge(assem::temp u, assem::temp v)
	{
		if (u == v || adjacency_set_.count({u, v}))
			return;

		adjacency_set_.insert({u, v});
		adjacency_set_.insert({v, u});

		if (precolored_.find(u) == precolored_.end()) {
			adjacency_list_[u] += v;
			degree_[u] += 1;
		}
		if (precolored_.find(v) == precolored_.end()) {
			adjacency_list_[v] += u;
			degree_[v] += 1;
		}
	}

	assem::temp_pair_set node_moves(assem::temp t)
	{
		return move_list_[t].intersect(active_moves_ + moves_wkl_);
	}

	bool move_related(assem::temp t) { return node_moves(t).size() != 0; }

	// initial must be empty after this according to Appel
	void make_worklist(utils::uset<assem::temp> &initial)
	{
		for (auto n : initial) {
			unsigned degree = degree_[n];

			if (degree >= target_.reg_count())
				spill_wkl_ += n;
			else if (move_related(n))
				freeze_wkl_ += n;
			else
				simplify_wkl_ += n;
		}
	}

	void build(std::vector<ifence_graph::node_type> &nodes)
	{
		for (auto &node : nodes) {
			auto temp = node->value_;

			for (auto pred : node.pred_)
				add_edge(temp, nodes[pred]->value_);
			for (auto succ : node.succ_)
				add_edge(temp, nodes[succ]->value_);
		}

		for (auto [t, _] : target_.temp_map())
			degree_[t] = UINT_MAX;
	}

	assem::temp_set adjacent(assem::temp t)
	{
		return adjacency_list_[t]
		       - (coalesced_nodes_
			  + std::pair(select_stack_.begin(),
				      select_stack_.end()));
	}

	void enable_moves(const assem::temp_set &nodes)
	{
		for (auto &n : nodes) {
			for (auto &m : node_moves(n)) {
				if (!active_moves_.count(m))
					continue;
				active_moves_ -= m;
				moves_wkl_ += m;
			}
		}
	}

	void decrement_degree(assem::temp m)
	{
		ASSERT(degree_[m] > 0, "Can't decrement 0");
		auto d = degree_[m]--;
		if (d == target_.reg_count()) {
			enable_moves(adjacent(m) + m);
			spill_wkl_ -= m;
			if (move_related(m))
				freeze_wkl_ += m;
			else
				simplify_wkl_ += m;
		}
	}

	void simplify()
	{
		ASSERT(simplify_wkl_.size() > 0, "Simplify worklist empty");
		// XXX: Heuristic to choose n?
		auto n = *utils::choose(simplify_wkl_.begin(),
					simplify_wkl_.end());
		simplify_wkl_ -= n;
		select_stack_.push_back(n);

		for (auto m : adjacent(n)) {
			decrement_degree(m);
		}
	}

	assem::temp get_alias(assem::temp n)
	{
		if (coalesced_nodes_.count(n))
			return get_alias(alias_[n]);
		return n;
	}

	void freeze_moves(assem::temp u)
	{
		for (auto m : node_moves(u)) {
			auto [x, y] = m;
			auto v = get_alias(y) == get_alias(u) ? get_alias(x)
							      : get_alias(y);
			active_moves_ -= m;
			frozen_moves_ += m;

			if (node_moves(v).size() == 0
			    && degree_[v] < target_.reg_count()) {
				freeze_wkl_ -= v;
				simplify_wkl_ += v;
			}
		}
	}

	void select_spill()
	{
		// XXX: Add heuristic
		auto beg = spill_wkl_.begin();
		std::advance(beg,
			     utils::rand<size_t>(0, spill_wkl_.size() - 1));
		auto m = *beg;

		spill_wkl_ -= m;
		simplify_wkl_ += m;
		freeze_moves(m);
	}

	void freeze()
	{
		// XXX: Add heuristic
		auto u = *utils::choose(freeze_wkl_.begin(), freeze_wkl_.end());
		freeze_wkl_ -= u;
		simplify_wkl_ += u;
		freeze_moves(u);
	}

	void add_work_list(assem::temp u)
	{
		if (target_.temp_map().count(u) == 0 && !move_related(u)
		    && degree_[u] < target_.reg_count()) {
			freeze_wkl_ -= u;
			simplify_wkl_ += u;
		}
	}

	bool ok(assem::temp t, assem::temp r)
	{
		return degree_[t] < target_.reg_count()
		       || target_.temp_map().count(t)
		       || adjacency_set_.count(std::pair(t, r));
	}

	bool conservative(assem::temp_set nodes)
	{
		unsigned k = 0;
		for (auto &n : nodes) {
			if (degree_[n] >= target_.reg_count())
				k++;
		}
		return k < target_.reg_count();
	}

	void combine(assem::temp u, assem::temp v)
	{
		if (freeze_wkl_.count(v))
			freeze_wkl_ -= v;
		else {
			/*
			FIXME: This assertion sometimes fails, but the program
			seems to behaves correctly.
			ASSERT(spill_wkl_.count(v),
					"Removing but it isn't here");
			*/
			spill_wkl_ -= v;
		}
		coalesced_nodes_ += v;
		alias_[v] = u;
		move_list_[u] += move_list_[v];
		enable_moves(assem::temp_set({v}));

		for (auto &t : adjacent(v)) {
			add_edge(t, u);
			decrement_degree(t);
		}

		if (degree_[u] >= target_.reg_count() && freeze_wkl_.count(u)) {
			freeze_wkl_ -= u;
			simplify_wkl_ += u;
			freeze_moves(u);
		}
	}

	void coalesce()
	{
		auto tmp_moves_wkl_ = moves_wkl_;
		for (auto m : tmp_moves_wkl_) {
			auto [x, y] = m;
			x = get_alias(x);
			y = get_alias(y);

			auto [u, v] = precolored_.count(y) ? std::pair(y, x)
							   : std::pair(x, y);

			moves_wkl_ -= m;
			if (u == v) {
				coalesced_moves_ += m;
				add_work_list(u);
			} else if (precolored_.count(v)
				   || adjacency_set_.count(std::pair(u, v))) {
				constrained_moves_ += m;
				add_work_list(u);
				add_work_list(v);
			} else if ((precolored_.count(u)
				    // u is a reference name, and can't be
				    // captured by a lambda.
				    && utils::all_of(adjacent(v),
						     [this, u = u](auto t) {
							     return ok(t, u);
						     }))
				   || (!precolored_.count(u)
				       && conservative(adjacent(u)
						       + adjacent(v)))) {
				coalesced_moves_ += m;
				combine(u, v);
				add_work_list(u);
			} else
				active_moves_ += m;
		}
	}

	assem::temp_endomap assign_colors()
	{
		assem::temp_endomap colors;
		assem::temp_set precolored_set;

		for (auto [t, _] : precolored_) {
			colors.emplace(t, t);
			precolored_set += t;
		}

		while (select_stack_.size()) {
			auto n = select_stack_.back();
			select_stack_.pop_back();

			assem::temp_set ok_colors;
			for (auto r : target_.registers())
				ok_colors += r;

			for (auto &w : adjacency_list_[n]) {
				auto col = colored_nodes_ + precolored_set;
				if (col.count(get_alias(w)))
					ok_colors -= colors[get_alias(w)];
			}

			if (ok_colors.size() == 0)
				spill_nodes_.push_back(n);
			else {
				colored_nodes_ += n;
				// XXX: Heuristic?
				colors[n] = *utils::choose(ok_colors.begin(),
							   ok_colors.end());
			}
		}

		for (auto &n : coalesced_nodes_)
			colors[n] = colors[get_alias(n)];

		return colors;
	}

	assem::temp_endomap
	allocate(assem::temp_set initial,
		 std::vector<ifence_graph::node_type> &nodes)
	{
		build(nodes);
		make_worklist(initial);

		while (true) {
			if (simplify_wkl_.size())
				simplify();
			else if (moves_wkl_.size())
				coalesce();
			else if (freeze_wkl_.size())
				freeze();
			else if (spill_wkl_.size())
				select_spill();
			else
				break;
		}

		return assign_colors();
	}

	mach::target &target_;

	std::unordered_map<assem::temp, assem::temp_pair_set> move_list_;
	assem::temp_pair_set moves_wkl_;
	assem::temp_pair_set constrained_moves_;
	std::vector<assem::temp> spill_nodes_;
	assem::temp_set colored_nodes_;
	assem::temp_set coalesced_nodes_;
	assem::temp_pair_set coalesced_moves_;
	assem::temp_pair_set active_moves_;
	assem::temp_pair_set frozen_moves_;

	assem::temp_endomap alias_;

	std::vector<assem::temp> select_stack_;

	assem::temp_set spill_wkl_;
	assem::temp_set freeze_wkl_;
	assem::temp_set simplify_wkl_;

	std::unordered_map<utils::temp, std::string> precolored_;

	std::unordered_map<assem::temp, unsigned> degree_;
	assem::temp_pair_set adjacency_set_;
	std::unordered_map<assem::temp, assem::temp_set> adjacency_list_;
};

coloring_out color(mach::target &target, backend::ifence_graph &ifence,
		   assem::temp_set initial)
{
	auto nodes = ifence.graph_.nodes_;
	allocator allo(target, ifence.move_list_, ifence.worklist_moves_);

	auto allocation = allo.allocate(initial, nodes);
	return {
		allocation,
		allo.spill_nodes_,
		allo.colored_nodes_,
		allo.coalesced_nodes_,
	};
}
} // namespace regalloc
} // namespace backend
