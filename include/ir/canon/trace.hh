#pragma once

#include "ir/canon/bb.hh"
#include "ir/ir.hh"
#include <unordered_map>

namespace ir
{
struct trace {
	tree::rnodevec instrs_;
};

std::vector<trace> create_traces(std::unordered_map<utils::label, bb> bbs,
				 utils::label prologue);
tree::rnodevec optimize_traces(std::vector<trace> &traces);
} // namespace ir
