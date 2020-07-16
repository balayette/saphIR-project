#include "backend/opt/peephole.hh"
#include "utils/assert.hh"
#include "utils/ref.hh"
#include <vector>
#include <regex>

namespace backend::opt
{

/*
 * pattern contains regex that must match before the lines are replaced by
 * output.
 * output format: xor \0, \0 : \x will be replaced with the xth group
 * for example:
 * mov \$0, (aa)
 * mov (bb), (cc)
 * => match vector : [aa, bb, cc]
 * XXX: x must be single digit
 */

std::string format_output(const std::string &s,
			  const std::vector<std::string> &matches)
{
	std::string ret;

	for (size_t i = 0; i < s.size(); i++) {
		char c = s[i];
		if (c != '\\') {
			ret += c;
			continue;
		}
		c = s[++i];
		ASSERT(c >= '0' && c <= '9', "Wrong match number");
		int idx = c - '0';
		ret += matches[idx];
	}

	return ret;
}

struct pass {
	pass(const std::string &name, const std::vector<std::regex> &pattern,
	     const std::vector<std::string> output)
	    : name_(name), pattern_(pattern), output_(output)
	{
	}
	virtual ~pass() = default;

	virtual std::vector<assem::rinstr>
	process_patt(std::vector<assem::rinstr>::iterator beg,
		     std::vector<assem::rinstr>::iterator end,
		     const std::vector<std::string> &matches) = 0;

	std::string name_;
	std::vector<std::regex> pattern_;
	std::vector<std::string> output_;
};

struct xor_pass : public pass {
	xor_pass(const std::string &name,
		 const std::vector<std::regex> &pattern,
		 const std::vector<std::string> output)
	    : pass(name, pattern, output)
	{
	}

	std::vector<assem::rinstr>
	process_patt(std::vector<assem::rinstr>::iterator beg,
		     std::vector<assem::rinstr>::iterator end,
		     const std::vector<std::string> &matches) override
	{
		(void)end;

		std::string repr = format_output(output_[0], matches);
		auto instr = new assem::sized_oper("xor", repr, (*beg)->dst_,
						   {}, (*beg)->dst_[0].size_);
		return {instr};
	}
};

#define R(X) std::regex(X)

std::vector<utils::ref<pass>> passes{
	new xor_pass("xor reg, reg", {R("mov \\$0, (`d0)")}, {"\\0, \\0"}),
};

void peephole(std::vector<assem::rinstr> &instrs)
{
reset:
	for (size_t i = 0; i < instrs.size(); i++) {
		for (auto pass : passes) {
			if (i + pass->pattern_.size() >= instrs.size())
				continue;

			bool cont = true;
			std::vector<std::string> vecmatches;

			for (size_t curr = 0;
			     cont && curr < pass->pattern_.size(); curr++) {
				// std::regex_match has deleted the rvalue
				// reference overload...
				auto repr = instrs[i + curr]->repr();

				std::smatch match;
				cont = std::regex_match(repr, match,
							pass->pattern_[curr]);
				for (unsigned i = 1; i < match.size(); i++)
					vecmatches.push_back(match[i].str());
			}

			if (!cont)
				continue;

			std::cout << "Pattern found: " << pass->name_ << '\n';

			auto updated = pass->process_patt(
				instrs.begin() + i,
				instrs.begin() + i + pass->pattern_.size() - 1,
				vecmatches);

			instrs.erase(instrs.begin() + i,
				     instrs.begin() + i
					     + pass->pattern_.size());
			instrs.insert(instrs.begin() + i, updated.begin(),
				      updated.end());
			goto reset;
		}
	}
}
} // namespace backend::opt
