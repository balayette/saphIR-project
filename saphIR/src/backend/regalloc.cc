#include "backend/regalloc.hh"
#include "utils/uset.hh"
#include "utils/assert.hh"
#include "mach/codegen.hh"
#include "ir/ir.hh"
#include <iostream>
#include "backend/color.hh"

namespace backend::regalloc
{
// Replace all uses of spilling temps by memory loads and stores
void rewrite(std::vector<assem::rinstr> &instrs,
	     std::vector<assem::temp> spills, mach::frame &f)
{
	std::unordered_map<assem::temp, utils::ref<mach::access>> temp_to_acc;

	for (auto &spill : spills) {
		auto acc = f.alloc_local(true);
		temp_to_acc.insert({spill, f.alloc_local(true)});
	}

	auto &target = f.target_;
	auto cgen = target.make_asm_generator();

	for (auto &inst : instrs) {
		std::vector<ir::tree::rstm> moves;

		for (auto &src : inst->src_) {
			if (std::find(spills.begin(), spills.end(), src)
			    == spills.end())
				continue;

			auto nsrc = cgen->codegen(temp_to_acc[src]->exp());
			nsrc.size_ = src.size_;
			nsrc.is_signed_ = src.is_signed_;

			src = nsrc;
		}

		for (auto &dst : inst->dst_) {
			if (std::find(spills.begin(), spills.end(), dst)
			    == spills.end())
				continue;

			assem::temp vi(unique_temp());
			moves.push_back(target.make_move(
				temp_to_acc[dst]->exp(),
				target.make_temp(vi, temp_to_acc[dst]->ty_)));

			dst = vi;
		}

		cgen->emit(inst);

		for (const auto &mv : moves)
			cgen->codegen(mv);
	}

	instrs = cgen->output();
}

// At this point, all temps are mapped to registers, so we just replace
// them in src_ and dst_
void replace_allocation(std::vector<assem::rinstr> &instrs,
			assem::temp_endomap &allocation)
{
	for (auto &inst : instrs) {
		if (inst.as<assem::label>())
			continue;

		for (auto &dst : inst->dst_) {
			auto it = allocation.find(dst);
			ASSERT(it != allocation.end(), "No allocation");

			// don't overwrite the size
			dst.temp_ = it->second;
		}

		for (auto &src : inst->src_) {
			auto it = allocation.find(src);
			ASSERT(it != allocation.end(), "No allocation");

			src.temp_ = it->second;
		}
	}

	std::vector<assem::rinstr> filterd;
	for (auto &inst : instrs) {
		// Remove redundant moves
		auto move = inst.as<assem::move>();
		if (move && move->removable())
			continue;

		filterd.push_back(inst);
	}

	instrs = filterd;
}

void alloc(std::vector<assem::rinstr> &instrs, mach::fun_fragment &f)
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
		backend::ifence_graph ifence(cfg.cfg_);

		coloring_out co = color(f.frame_->target_, ifence, initial);
		if (co.spills.size() == 0) {
			replace_allocation(instrs, co.allocation);
			break;
		} else {
			rewrite(instrs, co.spills, *f.frame_);
		}
	}
}
} // namespace backend::regalloc
