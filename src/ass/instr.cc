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
	return os << ins.repr();
}

instr::instr(const std::string &repr, std::vector<assem::temp> dst,
	     std::vector<assem::temp> src, std::vector<utils::label> jmps)
    : repr_(repr), dst_(dst), src_(src), jmps_(jmps)
{
}

std::string instr::repr() const { return repr_; }

std::string instr::to_string() const
{
	std::vector<std::string> src;
	std::vector<std::string> dst;

	for (auto &l : src_)
		src.push_back(l);
	for (auto &d : dst_)
		dst.push_back(d);

	return format_repr(repr(), src, dst);
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

	return format_repr(repr(), src, dst);
}

std::string
instr::to_string(std::function<std::string(utils::temp, unsigned)> f) const
{
	std::vector<std::string> src;
	std::vector<std::string> dst;

	for (auto &l : src_)
		src.push_back(f(l.temp_, l.size_));
	for (auto &l : dst_)
		dst.push_back(f(l.temp_, l.size_));

	return format_repr(repr(), src, dst);
}

oper::oper(const std::string &repr, std::vector<assem::temp> dst,
	   std::vector<assem::temp> src, std::vector<utils::label> jmps)
    : instr(repr, dst, src, jmps)
{
}

sized_oper::sized_oper(const std::string &oper_str, const std::string &op,
		       std::vector<assem::temp> dst,
		       std::vector<assem::temp> src, unsigned sz)
    : oper(oper_str + " " + op, dst, src, {}), oper_str_(oper_str), op_(op),
      sz_(sz)
{
}

std::string
sized_oper::to_string(std::function<std::string(utils::temp, unsigned)> f) const
{
	std::string repr = oper_str_ + size_str(sz_);

	std::vector<std::string> src;
	std::vector<std::string> dst;

	for (auto &l : src_)
		src.push_back(f(l.temp_, l.size_));
	for (auto &d : dst_)
		dst.push_back(f(d.temp_, d.size_));

	return format_repr(repr + " " + op_, src, dst);
}

jump::jump(const std::string &repr, std::vector<assem::temp> src,
	   std::vector<utils::label> jumps)
    : oper(repr, {}, src, jumps)
{
}

lea::lea(assem::temp dst, std::pair<std::string, assem::temp> src)
    : oper("LEA", {dst}, {src.second}, {}), lhs_(src.first)
{
}

lea::lea(assem::temp dst, std::string src)
    : oper("LEA", {dst}, {}, {}), lhs_(src)
{
}

std::string lea::repr() const { return "lea " + lhs_ + ", `d0"; }

label::label(const std::string &repr, utils::label lab)
    : instr(repr, {}, {}, {}), lab_(lab)
{
}

move::move(const std::string &dst_str, const std::string &src_str,
	   std::vector<assem::temp> dst, std::vector<assem::temp> src)
    : instr("mov " + src_str + ", " + dst_str, dst, src, {}), dst_str_(dst_str),
      src_str_(src_str)
{
}

std::string size_str(unsigned sz)
{
	if (sz == 1)
		return "b";
	else if (sz == 2)
		return "w";
	else if (sz == 4)
		return "l";
	else if (sz == 8)
		return "q";
	else
		UNREACHABLE("Size != 1, 2, 4, 8");
}

std::string
move::to_string(std::function<std::string(utils::temp, unsigned)> f) const
{
	assem::temp src = src_[0];
	assem::temp dst = dst_[0];
	unsigned ssize = src.size_;
	unsigned dsize = dst.size_;
	std::string move_kind = "mov";

	std::cout << "to_string " << src_str_ << ", " << dst_str_ << " "
		  << ssize << " -> " << dsize << '\n';

	if (ssize > dsize)
		ssize = dsize; // mov %rax, %ebx => mov %eax, %ebx

	if (ssize == dsize)
		move_kind += size_str(ssize);
	else if (ssize < dsize)
		move_kind += "s" + size_str(ssize) + size_str(dsize);

	return format_repr(move_kind + " " + src_str_ + ", " + dst_str_,
			   {f(src.temp_, ssize)}, {f(dst.temp_, dsize)});
}

simple_move::simple_move(assem::temp dst, assem::temp src)
    : move("`d0", "`s0", {dst}, {src})
{
}

complex_move::complex_move(const std::string &dst_str,
			   const std::string &src_str,
			   std::vector<assem::temp> dst,
			   std::vector<assem::temp> src, unsigned dst_sz,
			   unsigned src_sz)
    : move(dst_str, src_str, dst, src), dst_sz_(dst_sz), src_sz_(src_sz)
{
}

std::string complex_move::to_string(
	std::function<std::string(utils::temp, unsigned)> f) const
{
	unsigned ssize = src_sz_;
	unsigned dsize = dst_sz_;
	std::string move_kind = "mov";

	std::cout << "to_string " << src_str_ << ", " << dst_str_ << " "
		  << ssize << " -> " << dsize << '\n';

	if (ssize == dsize)
		move_kind += size_str(ssize);
	else if (ssize < dsize)
		move_kind += "s" + size_str(ssize) + size_str(dsize);
	else
		move_kind += size_str(dsize);


	std::vector<std::string> src;
	std::vector<std::string> dst;

	for (auto &l : src_)
		src.push_back(f(l.temp_, l.size_));
	for (auto &d : dst_)
		dst.push_back(f(d.temp_, d.size_));

	return format_repr(move_kind + " " + src_str_ + ", " + dst_str_, src,
			   dst);
}
} // namespace assem
