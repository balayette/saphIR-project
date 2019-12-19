#include "ass/instr.hh"

namespace assem
{
std::string format_repr(std::string repr, std::vector<utils::temp> src,
			std::vector<utils::temp> dst)
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
			ret += src[idx].get();
		else
			ret += dst[idx].get();
	}

	return ret;
}

std::ostream &operator<<(std::ostream &os, const instr &ins)
{
	return os << ins.repr_;
}

instr::instr(const std::string &repr, std::vector<utils::temp> dst,
	     std::vector<utils::temp> src, std::vector<utils::label> jmps)
    : repr_(repr), dst_(dst), src_(src), jmps_(jmps)
{
}

std::string instr::to_string() const { return format_repr(repr_, src_, dst_); }

oper::oper(const std::string &repr, std::vector<utils::temp> dst,
	   std::vector<utils::temp> src, std::vector<utils::label> jmps)
    : instr(repr, dst, src, jmps)
{
}

label::label(const std::string &repr, utils::label lab)
    : instr(repr, {}, {}, {}), lab_(lab)
{
}

move::move(const std::string &repr, std::vector<utils::temp> dst,
	   std::vector<utils::temp> src)
    : instr(repr, dst, src, {})
{
}
} // namespace assem
