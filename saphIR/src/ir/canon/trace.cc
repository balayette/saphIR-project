#include "ir/canon/trace.hh"
#include "ir/ops.hh"
#include "utils/uset.hh"
#include "utils/assert.hh"
#include "mach/target.hh"

namespace ir
{
std::vector<trace> create_traces(std::unordered_map<utils::label, bb> bbs,
				 utils::label prologue)
{
	utils::uset<utils::label> visited;
	std::vector<bb> blocks;
	std::vector<trace> ret;

	for (auto [l, b] : bbs) {
		if (l != prologue)
			blocks.push_back(b);
	}
	blocks.push_back(bbs.find(prologue)->second);

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
		auto &target = instr->target();
		if (auto cj = instr.as<tree::cjump>()) {
			auto lbl = i + 1 == instrs.size()
					   ? nullptr
					   : instrs[i + 1].as<tree::label>();
			auto correct_label = lbl
					     && (lbl->name_ == cj->lfalse_
						 || lbl->name_ == cj->ltrue_);
			if (i + 1 == instrs.size() || !correct_label) {
				// The final instruction is a cjump, or the
				// cjump is not followed by one of its labels,
				// we expand it.
				utils::label lab;
				auto ncj = target.make_cjump(cj->op_, cj->lhs(),
							     cj->rhs(),
							     cj->ltrue_, lab);
				auto newlab = target.make_label(lab);
				auto jmpold = target.make_jump(
					target.make_name(cj->lfalse_),
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
				ASSERT("cjump {} {} followed by wrong label {}",
				       std::string(cj->ltrue_),
				       std::string(cj->lfalse_),
				       std::string(lbl->name_));
				if (lbl->name_ == cj->lfalse_)
					continue;

				// The cjump is followed by its true
				// label, we swap the labels and the
				// condition.
				std::swap(cj->ltrue_, cj->lfalse_);
				cj->op_ = ops::invert_cmpop(cj->op_);
			}
		}

		if (auto j = instrs[i].as<tree::jump>()) {
			if (i + 1 == instrs.size()
			    || j->avlbl_dests_.size() > 1)
				continue;

			// If we're followed by our label, remove the jump.
			if (auto lb = instrs[i + 1].as<tree::label>()) {
				if (lb->name_ == j->avlbl_dests_[0])
					instrs.erase(instrs.begin() + i);
			}
		}
	}
}

tree::rnodevec optimize_traces(std::vector<trace> &traces)
{
	tree::rnodevec ret;
	for (auto &t : traces)
		ret.insert(ret.end(), t.instrs_.begin(), t.instrs_.end());

	optimize_trace(ret);

	return ret;
}
} // namespace ir
