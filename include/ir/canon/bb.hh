#pragma once

#include "ir/ir.hh"
#include <unordered_map>

namespace ir
{
struct bb {
	bb(tree::rnodevec::iterator begin, tree::rnodevec::iterator end);

	std::vector<utils::label> successors();
	utils::label entry();

	tree::rnodevec instrs_;
};

std::unordered_map<utils::label, bb>
create_bbs(tree::rnode stm, utils::label &body, utils::label epilogue);
} // namespace ir
