#include "ass/instr.hh"
#include "utils/assert.hh"

namespace assem
{
std::string format_repr(std::string repr, std::vector<std::string> src,
			std::vector<std::string> dst)
{
	std::string ret;

	for (unsigned i = 0; i < repr.size(); i++) {
		char c = repr[i];
		if (c != '`') {
			ret += c;
			continue;
		}
		c = repr[++i];
		ASSERT(c == 's' || c == 'd', "Wrong register placeholder");
		bool source = c == 's';
		c = repr[++i];
		ASSERT(c >= '0' && c <= '9', "Wrong register number");
		unsigned idx = c - '0';
		if (source) {
			ASSERT(idx < src.size(),
			       "Source register out of bounds");
			ret += src[idx];
		} else {
			ASSERT(idx < dst.size(),
			       "Destination register out of bounds");
			ret += dst[idx];
		}
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

std::string instr::to_string() const
{
	std::vector<std::string> src;
	std::vector<std::string> dst;

	for (auto &l : src_)
		src.push_back(l);
	for (auto &d : dst_)
		dst.push_back(d);

	return format_repr(repr_, src, dst);
}

std::string
instr::to_string(const std::unordered_map<utils::temp, std::string> &map) const
{
	std::vector<std::string> src;
	std::vector<std::string> dst;

	for (auto &l : src_)
		src.push_back(map.find(l)->second);
	for (auto &d : dst_)
		dst.push_back(map.find(d)->second);

	return format_repr(repr_, src, dst);
}

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
