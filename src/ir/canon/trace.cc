#include "ir/canon/trace.hh"
#include "frontend/ops.hh"
#include <unordered_set>

namespace backend
{
std::vector<trace> create_traces(std::unordered_map<::temp::label, bb> bbs)
{
	std::unordered_set<::temp::label> visited;
	std::vector<bb> blocks;
	std::vector<trace> ret;
	for (auto [_, b] : bbs)
		blocks.push_back(b);

	while (blocks.size() > 0) {
		trace t;
		auto b = blocks.back();
		blocks.pop_back();
		while (!visited.count(b.entry())) {
			visited.emplace(b.entry());
			t.instrs_.insert(t.instrs_.end(), b.instrs_.begin(),
					 b.instrs_.end());

			for (auto s : b.successors()) {
				if (!visited.count(s)) {
					std::cout << s << " is not visited\n";
					auto it = bbs.find(s);
					if (it == bbs.end())
						continue;
					b = it->second;
				}
			}
		}

		if (t.instrs_.size() > 0)
			ret.push_back(t);
	}

	return ret;
}

void optimize_trace(tree::rnodevec &instrs)
{
	for (unsigned i = 0; i < instrs.size(); i++) {
		auto instr = instrs[i];
		if (auto cj = instr.as<tree::cjump>()) {
			if (i + 1 == instrs.size()) {
				std::cout << "cjump expansion\n";
				// The final instruction is a cjump, we expand
				// it.
				::temp::label lab;
				auto ncj = new tree::cjump(cj->op_, cj->lhs(),
							   cj->rhs(),
							   cj->ltrue_, lab);
				auto newlab = new tree::label(lab);
				auto jmpold = new tree::jump(
					new tree::name(cj->lfalse_),
					{cj->lfalse_});

				// Remove the old cjump
				instrs.pop_back();
				// And replace it with
				// CJUMP ... newlab
				// newlab
				// jump oldlab
				instrs.emplace_back(ncj);
				instrs.emplace_back(newlab);
				instrs.emplace_back(jmpold);
				i += 2;
			} else {
				// The next element has to be a label, we check
				// if it is the false label.
				auto lbl = instrs[i + 1].as<tree::label>();
				if (lbl->name_ == cj->lfalse_)
					continue;

				std::cout << "cjump inversion\n";
				// The cjump is followed by its false label,
				// we swap the labels and the condition.
				std::swap(cj->ltrue_, cj->lfalse_);
				cj->op_ = ops::invert_cmpop(cj->op_);
			}
		}

		if (auto j = instrs[i].as<tree::jump>()) {
			if (i + 1 == instrs.size())
				continue;

			// If we're followed by our label, remove the jump.
			// We're always followed by our label if we're not the
			// last in the trace.
			std::cout << "Remove useless jump\n";
			instrs.erase(instrs.begin() + i);
		}
	}
}

void optimize_traces(std::vector<trace> &traces)
{
	for (auto &t : traces)
		optimize_trace(t.instrs_);
}
} // namespace backend
