#include "ass/instr.hh"

namespace assem
{
std::string format_repr(std::string repr, std::vector<::temp::temp> src,
			std::vector<::temp::temp> dst)
{
	std::string ret;

	for (unsigned i = 0; i < repr.size(); i++) {
		char c = repr[i];
		if (c != '`') {
			ret += c;
			continue;
		}
		c = repr[++i];
		bool source = c == 's';
		c = repr[++i];
		int idx = c - '0';
		if (source)
			ret += src[idx].sym_.get();
		else
			ret += dst[idx].sym_.get();
	}

	return ret;
}

instr::instr(const std::string &repr, std::vector<::temp::temp> dst,
	     std::vector<::temp::temp> src, std::vector<::temp::label> jmps)
    : repr_(repr), dst_(dst), src_(src), jmps_(jmps)
{
}

std::string instr::to_string() const { return format_repr(repr_, src_, dst_); }

oper::oper(const std::string &repr, std::vector<::temp::temp> dst,
	   std::vector<::temp::temp> src, std::vector<::temp::label> jmps)
    : instr(repr, dst, src, jmps)
{
}

label::label(const std::string &repr, ::temp::label lab)
    : instr(repr, {}, {}, {}), lab_(lab)
{
}

move::move(const std::string &repr, std::vector<::temp::temp> dst,
	   std::vector<::temp::temp> src)
    : instr(repr, dst, src, {})
{
}
} // namespace assem
