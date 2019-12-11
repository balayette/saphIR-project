#pragma once

#include "ir/ir.hh"
#include <unordered_map>

namespace ir
{
::temp::label done_lbl();

struct bb {
	bb(tree::rnodevec::iterator begin, tree::rnodevec::iterator end);

	std::vector<::temp::label> successors();
	::temp::label entry();

	tree::rnodevec instrs_;
};

std::unordered_map<::temp::label, bb> create_bbs(tree::rnode stm,
						 ::temp::label &prologue);
} // namespace ir
