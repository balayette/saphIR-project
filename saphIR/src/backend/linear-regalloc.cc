#include "backend/linear-regalloc.hh"
#include "backend/regalloc.hh"
#include "utils/random.hh"
#include "utils/timer.hh"
#include "backend/dataflow.hh"
#include <sstream>
#include <fstream>

#define LOG_LINEAR_REGALLOC 0

#if LOG_LINEAR_REGALLOC
#define LINEAR_LOG(...) fmt::print(__VA_ARGS__)
#else
#define LINEAR_LOG(...)
#endif

namespace backend::regalloc
{
struct interval {
	interval() : allocation(std::nullopt) {}

	interval(const utils::temp &temp, utils::node_id beg,
		 utils::node_id end)
	    : temp(temp), beg(beg), end(end), spilled(false),
	      allocation(std::nullopt)
	{
	}

	utils::temp temp;
	utils::node_id beg;
	utils::node_id end;

	bool spilled;
	std::optional<utils::temp> allocation;
};

void dump_intervals(const std::vector<interval> &intervals)
{
	for (const auto &it : intervals) {
		std::stringstream str;
		str << it.temp;
		while (str.str().size() < 10)
			str << " ";
		str << "| ";
		if (it.allocation)
			str << *it.allocation;
		else if (it.spilled)
			str << "spilled";
		else
			str << "noalloc";
		while (str.str().size() < 25)
			str << " ";
		str << "| ";
		for (size_t i = 0; i < it.beg; i++)
			str << ' ';
		for (size_t i = it.beg; i < it.end; i++)
			str << '#';
		std::cout << str.str() << '\n';
	}
}

struct linear_allocator {
	linear_allocator(mach::target &target)
	    : target(target), registers(target.registers())
	{
	}

	std::vector<assem::temp> alloc(backend::cfg cfg)
	{
		free_registers.clear();
		intervals.clear();
		active.clear();

		for (auto &r : registers)
			free_registers += r;

		auto [in, out] = dataflow_analysis(cfg.graph());

		std::unordered_map<utils::temp, interval> range_map;

#if LOG_LINEAR_REGALLOC
		for (utils::node_id n = 0; n < cfg.graph().size(); n++) {
			auto &node = cfg.graph().nodes()[n];
			fmt::print("{}       | Defs:", node->debug);
			for (const auto &d : cfg.graph().get(n)->def)
				fmt::print(" {}", std::string(d));
			fmt::print(" | Uses:");
			for (const auto &d : cfg.graph().get(n)->use)
				fmt::print(" {}", std::string(d));
			fmt::print("\n");

			fmt::print("  ");
			for (const auto &o : in[n])
				fmt::print(" {}", std::string(o));
			fmt::print("\n");
			fmt::print("  ");
			for (const auto &o : out[n])
				fmt::print(" {}", std::string(o));
			fmt::print("\n");
		}
#endif

		for (utils::node_id n = 0; n < cfg.graph().size(); n++) {
			assem::temp_set ins = in[n] + out[n];
			for (auto &t : ins) {
				if (range_map.find(t) == range_map.end()) {
					range_map.insert(
						{t, interval{t, n, n}});
				} else {
					range_map[t].beg =
						std::min(range_map[t].beg, n);
					range_map[t].end =
						std::max(range_map[t].end, n);
				}
			}
		}

		for (utils::node_id n = 0; n < cfg.graph().size(); n++) {
			const auto *node = cfg.graph().get(n);
			for (const auto &u : node->use)
				ASSERT(range_map.count(u),
				       "{} (used) is not in the range map",
				       std::string(u));
			for (const auto &d : node->def)
				range_map.insert({d, interval(d, n, n)});
		}

#if LOG_LINEAR_REGALLOC
		for (auto &[k, v] : range_map) {
			std::cout << "Temp " << k << " live from " << v.beg
				  << " to " << v.end << "\n";
		}
#endif

		for (const auto &[k, v] : range_map)
			intervals.push_back(v);

		std::sort(intervals.begin(), intervals.end(),
			  [&](const auto &r1, const auto &r2) {
				  return r1.beg < r2.beg;
			  });

#if LOG_LINEAR_REGALLOC
		dump_intervals(intervals);
#endif

		std::vector<assem::temp> spills;

		for (auto &itv : intervals) {
			expire(itv);

			if (!free_registers.size()) {
				spills.push_back(spill_for(itv));
				continue;
			}

			auto spill = allocate(itv);
			if (spill)
				spills.push_back(*spill);
			else
				add_active(&itv);
		}

#if LOG_LINEAR_REGALLOC
		dump_intervals(intervals);
#endif

		return spills;
	}

	void add_active(interval *itv)
	{
		active.insert(
			std::upper_bound(active.begin(), active.end(), itv,
					 [&](const auto &a, const auto &b) {
						 return a->end < b->end;
					 }),
			itv);
	}

	void expire(interval &i)
	{
		while (true) {
			if (active.size() == 0)
				break;

			auto &j = active[0];
			if (j->end >= i.beg)
				return;

			free(*j);
			active.erase(active.begin());
		}
	}

	utils::temp spill_for(interval &itv)
	{
		if (registers.count(itv.temp)) {
			/* The physical register than itv needs is already
			 * allocated.
			 */
			auto to_spill = std::find_if(
				active.begin(), active.end(),
				[&](const auto &i) {
					return i->allocation == itv.temp;
				});
			ASSERT(to_spill != active.end(),
			       "Allocation not found");

			// Satisfy the allocation request
			itv.allocation = itv.temp;
			// Spill the other one to a temporary
			auto ret = (*to_spill)->temp;
			(*to_spill)->allocation = std::nullopt;
			(*to_spill)->spilled = true;
			// remove it from actives
			active.erase(to_spill);
			// And add the allocated register to actives
			add_active(&itv);
			return ret;
		}

		/*
		 * This is a normal spill, where there is simply too much
		 * register pressure. Choose which interval to spill depending
		 * on its end
		 */
		LINEAR_LOG("Too much register pressure, spilling...\n");
		auto to_spill_it = active.end() - 1;
		auto *to_spill = *to_spill_it;
		while (registers.count(to_spill->temp)) {
			LINEAR_LOG("  Not spilling {}\n",
				   std::string(to_spill->temp));
			to_spill_it--;
			to_spill = *to_spill_it;
		}

		if (to_spill->end > itv.end) {
			LINEAR_LOG("  Spilling {} (was allocated to {})\n",
				   std::string(to_spill->temp),
				   std::string(*to_spill->allocation));
			itv.allocation = *to_spill->allocation;
			to_spill->allocation = std::nullopt;
			to_spill->spilled = true;
			auto ret = to_spill->temp;
			active.erase(to_spill_it);
			add_active(&itv);
			return ret;
		} else {
			itv.allocation = std::nullopt;
			itv.spilled = true;
			return itv.temp;
		}
	}

	void free(interval &itv)
	{
		ASSERT(itv.allocation != std::nullopt,
		       "Freeing {}, but not allocated", std::string(itv.temp));

		LINEAR_LOG("Freeing {} ({} was allocated to it)\n",
			   std::string(*itv.allocation), std::string(itv.temp));
		free_registers += *itv.allocation;
	}

	std::optional<utils::temp> allocate(interval &itv)
	{
		ASSERT(free_registers.size(), "Not enough regs");

		if (registers.count(itv.temp)) {
			if (free_registers.count(itv.temp)) {
				free_registers -= itv.temp;
				itv.allocation = itv.temp;
				LINEAR_LOG("Allocated physical register {}\n",
					   std::string(itv.temp));
				return std::nullopt;
			}

			auto ret = spill_for(itv);
			LINEAR_LOG(
				"Allocated physical register {} after spilling {}\n",
				std::string(itv.temp), std::string(ret));
			return ret;
		}

		auto ret = *utils::choose(free_registers.begin(),
					  free_registers.end());
		free_registers -= ret;
		LINEAR_LOG("Allocating {} to {}\n", std::string(itv.temp),
			   std::string(ret));
		itv.allocation = ret;

		return std::nullopt;
	}

	assem::temp_endomap allocations()
	{
		assem::temp_endomap ret;

		for (const auto &itv : intervals) {
			ASSERT(itv.allocation,
			       "Interval for {} is spilled or not allocated",
			       std::string(itv.temp));

			ret.insert({itv.temp, *itv.allocation});
		}

		for (const auto &r : registers) {
			ret.insert({r, r});
		}

		return ret;
	}

	mach::target &target;

	std::vector<interval> intervals;
	std::vector<interval *> active;

	utils::temp_set free_registers;
	utils::temp_set registers;
};

void linear_alloc(std::vector<assem::rinstr> &instrs, mach::fun_fragment &f)
{
	linear_allocator allocator(f.frame_->target_);

	for (size_t loop_count = 1;; loop_count++) {
		backend::cfg cfg(instrs, f.body_lbl_);

		auto spills = allocator.alloc(cfg);
		if (!spills.size()) {
			LINEAR_LOG("Linear allocation succeeded after {}.\n",
				   loop_count);
			replace_allocations(instrs, allocator.allocations());
			break;
		} else {
			LINEAR_LOG("{} spills, rewriting\n", spills.size());
			rewrite(instrs, spills, *f.frame_);
		}
	}
}
} // namespace backend::regalloc
