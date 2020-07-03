#include "mach/amd64/amd64-instr.hh"

namespace assem::amd64
{
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

	return assem::format_repr(repr + " " + op_, src, dst);
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

std::string simple_move::to_string(
	std::function<std::string(utils::temp, unsigned)> f) const
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

	/*
	 * amd64 is weird, and writing to the lower half of a register zeroes
	 * the upper half.
	 * Thus, there is no movzlq instruction, which is better written
	 * as movl %reg, %reg
	 */
	if (dst.is_signed_ == types::signedness::UNSIGNED && dsize == 8
	    && ssize == 4)
		dsize = 4;

	if (ssize == dsize)
		move_kind += size_str(ssize);
	else if (ssize < dsize) {
		ASSERT(dst.is_signed_ != types::signedness::INVALID,
		       "Invalid signedness");
		if (dst.is_signed_ == types::signedness::SIGNED)
			move_kind += "s";
		else
			move_kind += "z";
		move_kind += size_str(ssize) + size_str(dsize);
	}

	return assem::format_repr(move_kind + " " + src_str_ + ", " + dst_str_,
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
			   unsigned src_sz, types::signedness sign)
    : move(dst_str, src_str, dst, src), dst_sz_(dst_sz), src_sz_(src_sz),
      sign_(sign)
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
	else if (ssize < dsize) {
		ASSERT(sign_ != types::signedness::INVALID,
		       "Invalid signedness");
		if (sign_ == types::signedness::SIGNED)
			move_kind += "s";
		else
			move_kind += "z";
		move_kind += size_str(ssize) + size_str(dsize);
	} else
		move_kind += size_str(dsize);


	std::vector<std::string> src;
	std::vector<std::string> dst;

	for (auto &l : src_)
		src.push_back(f(l.temp_, l.size_));
	for (auto &d : dst_)
		dst.push_back(f(d.temp_, d.size_));

	return assem::format_repr(move_kind + " " + src_str_ + ", " + dst_str_,
				  src, dst);
}

} // namespace assem::amd64
