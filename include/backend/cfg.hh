#pragma once

#include "utils/graph.hh"
#include "utils/temp.hh"
#include "ass/instr.hh"
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <iostream>

namespace backend
{
struct cfgnode {
	cfgnode(std::vector<::temp::temp> def, std::vector<::temp::temp> use,
		bool is_move);
	std::vector<::temp::temp> def;
	std::vector<::temp::temp> use;
	bool is_move;
	std::string debug;
};

std::ostream &operator<<(std::ostream &os, const cfgnode &node);

class cfg
{
      public:
	cfg(std::vector<assem::rinstr> instrs, ::temp::label prologue);
	utils::graph<cfgnode> cfg_;

      private:
	void build(unsigned idx, std::optional<unsigned> pred);
	std::vector<assem::rinstr> instrs_;
	std::unordered_map<::temp::label, unsigned> label_to_node_;
	std::unordered_map<unsigned, unsigned> visited_;
};
} // namespace backend
