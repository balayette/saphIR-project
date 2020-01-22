#include "ir/opt/peephole.hh"
#include <memory>

namespace ir
{
struct ipattern {
	tree::tree_kind kind;
	std::vector<ipattern> children;
};

struct optimization {
	optimization(const std::string &n) : name(n) {}
	const std::string name;
	std::vector<ipattern> pattern;

	virtual tree::rnodevec process(tree::rnodevec::iterator beg,
				       tree::rnodevec::iterator end) = 0;

	virtual ~optimization() = default;
};

ipattern cnst{tree::tree_kind::cnst, {}};
ipattern temp{tree::tree_kind::temp, {}};

ipattern reg_cnst_binop{tree::tree_kind::binop, {temp, cnst}};
ipattern mov_temp_cnst_binop{tree::tree_kind::move, {temp, reg_cnst_binop}};

ipattern mem_temp{tree::tree_kind::mem, {temp}};
ipattern move_mem_temp_temp{tree::tree_kind::move, {mem_temp, temp}};

struct stack_access : public optimization {
	stack_access() : optimization("stack access")
	{
		pattern = {mov_temp_cnst_binop, move_mem_temp_temp};
	}

	tree::rnodevec process(tree::rnodevec::iterator beg,
			       tree::rnodevec::iterator end) override
	{
		auto mov1 = beg->as<tree::move>();
		auto mov2 = end->as<tree::move>();

		auto temp = mov1->lhs().as<tree::temp>();
		auto binop = mov1->rhs().as<tree::binop>();

		auto mem = mov2->lhs().as<tree::mem>();
		auto dest = mov2->rhs().as<tree::temp>();

		auto src = mem->e().as<tree::temp>();

		return {new tree::move(new tree::mem(binop), src)};
	}
};


bool matches_instr(tree::rnode &instr, ipattern &ip)
{
	if (instr->kind() != ip.kind)
		return false;

	if (ip.children.size() != instr->children_.size())
		return false;

	for (size_t i = 0; i < ip.children.size(); i++) {
		if (!matches_instr(instr->children_[i], ip.children[i]))
			return false;
	}
	return true;
}

void peephole(tree::rnodevec &trace)
{
	std::vector<utils::ref<optimization>> optis{new stack_access};

reset:
	for (size_t i = 0; i < trace.size(); i++) {
		for (auto &opti : optis) {
			if (i + opti->pattern.size() >= trace.size())
				continue;

			bool cont = true;
			for (size_t curr = 0;
			     cont && curr < opti->pattern.size(); curr++) {
				cont = matches_instr(trace[i + curr],
						     opti->pattern[curr]);
			}

			if (!cont)
				continue;

			std::cout << "Pattern found: " << opti->name << '\n';
			auto updated = opti->process(
				trace.begin() + i,
				trace.begin() + i + opti->pattern.size() - 1);

			trace.erase(trace.begin() + i,
				    trace.begin() + i + opti->pattern.size());
			trace.insert(trace.begin() + i, updated.begin(),
				     updated.end());
			goto reset;
		}
	}
}
} // namespace ir
