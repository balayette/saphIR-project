#pragma once

#include "utils/graph.hh"
#include "utils/temp.hh"
#include "ass/instr.hh"
#include "utils/uset.hh"
#include <unordered_map>
#include <optional>
#include <iostream>

namespace backend
{
struct cfgnode {
	cfgnode(utils::uset<utils::temp> def,
		utils::uset<utils::temp> use, bool is_move);
	utils::uset<utils::temp> def;
	utils::uset<utils::temp> use;
	bool is_move;
	std::string debug;
};

std::ostream &operator<<(std::ostream &os, const cfgnode &node);

class cfg
{
      public:
	cfg(std::vector<assem::rinstr> instrs, utils::label prologue);
	utils::graph<cfgnode> cfg_;

      private:
	void build(unsigned idx, std::optional<utils::node_id> pred);
	std::vector<assem::rinstr> instrs_;
	std::unordered_map<utils::label, unsigned> label_to_node_;
	std::unordered_map<unsigned, utils::node_id> visited_;
};
} // namespace backend
