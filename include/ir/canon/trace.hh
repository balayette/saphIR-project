#pragma once

#include "ir/canon/bb.hh"
#include "ir/ir.hh"
#include <unordered_map>

namespace backend
{
struct trace {
	tree::rnodevec instrs_;
};

std::vector<trace> create_traces(std::unordered_map<::temp::label, bb> bbs);
void optimize_traces(std::vector<trace> &traces);
} // namespace backend
