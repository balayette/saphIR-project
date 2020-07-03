#include "mach/aarch64/aarch64-instr.hh"

namespace assem::aarch64
{
std::string size_str(unsigned sz)
{
	if (sz == 1)
		return "b";
	else if (sz == 2)
		return "h";
	else if (sz == 4)
		return "w";
	else if (sz == 8)
		return "";
	else
		UNREACHABLE("Size != 1, 2, 4, 8");
}

simple_move::simple_move(assem::temp dst, assem::temp src)
    : move("`s0", "`d0", {dst}, {src})
{
}

std::string simple_move::to_string(
	std::function<std::string(utils::temp, unsigned)> f) const
{
	assem::temp src = src_[0];
	assem::temp dst = dst_[0];
	unsigned ssize = src.size_;
	unsigned dsize = dst.size_;

	std::string repr;

	if (ssize > dsize)
		ssize = dsize; // mov w2, x1 => mov w2, w1

	if (ssize < dsize) {
		ASSERT(dst.is_signed_ != types::signedness::INVALID,
		       "Invalid signedness");
		if (dst.is_signed_ == types::signedness::SIGNED) {
			repr = "sxt";
			repr += size_str(ssize);
		} else {
			repr += "uxt";
			repr += size_str(ssize);
		}
	} else
		repr = "mov";

	repr += " `d0, `s0";

	return assem::format_repr(repr, {f(src.temp_, ssize)},
				  {f(dst.temp_, dsize)});
}

load::load(assem::temp dst, assem::temp src, unsigned sz)
    : oper("ldr `d0, [`s0]", {dst}, {src}, {}), sz_(sz)
{
}

std::string
load::to_string(std::function<std::string(utils::temp, unsigned)> f) const
{
	assem::temp src = src_[0];
	assem::temp dst = dst_[0];

	std::string repr("ldr");
	repr += size_str(dst.size_);
	repr += " `d0, [`s0]";

	return assem::format_repr(repr, {f(src.temp_, 8)},
				  {f(dst.temp_, dst.size_)});
}

store::store(assem::temp addr, assem::temp value, unsigned sz)
    : oper("str `s1, [`s0]", {}, {addr, value}, {}), sz_(sz)
{
}

std::string
store::to_string(std::function<std::string(utils::temp, unsigned)> f) const
{
	assem::temp addr = src_[0];
	assem::temp value = src_[1];

	std::string repr("str");
	repr += size_str(sz_);
	repr += " `s1, [`s0]";

	return assem::format_repr(
		repr, {f(addr.temp_, 8), f(value.temp_, sz_ == 8 ? 8 : 4)}, {});
}
} // namespace assem::aarch64
