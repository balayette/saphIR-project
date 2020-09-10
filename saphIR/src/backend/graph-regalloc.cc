#include "backend/regalloc.hh"
#include "utils/uset.hh"
#include "utils/assert.hh"
#include "mach/codegen.hh"
#include "ir/ir.hh"
#include <iostream>
#include "backend/color.hh"

namespace backend::regalloc
{
void graph_alloc(std::vector<assem::rinstr> &instrs, mach::fun_fragment &f)
{
	auto precolored = f.frame_->target_.temp_map();

	for (size_t loop_count = 0;; loop_count++) {
		assem::temp_set initial;
		for (auto &inst : instrs) {
			for (auto &dest : inst->dst_) {
				if (!precolored.count(dest))
					initial += dest;
			}
			for (auto &src : inst->src_) {
				if (!precolored.count(src))
					initial += src;
			}
		}

		backend::cfg cfg(instrs, f.body_lbl_);
		backend::ifence_graph ifence(cfg.graph());

		coloring_out co = color(f.frame_->target_, ifence, initial);
		if (co.spills.size() == 0) {
			replace_allocations(instrs, co.allocation);
			break;
		} else {
			rewrite(instrs, co.spills, *f.frame_);
		}
	}
}
} // namespace backend::regalloc
