#pragma once

#include "symbol.hh"
#include "temp.hh"
#include <vector>
#include <variant>

/*
 * x86_64 calling convention:
 * RDI, RSI, RDX, RCX, R8, R9, (R10 = static link), stack (right to left)
 *
 * fun f(a, b, c, d, e, f, g, h)
 *
 * fp + 24	-> h
 * fp + 16	-> g
 * fp + 8 	-> ret addr
 * fp		-> saved fp
 * fp + ... 	-> local variables
 */

namespace frame
{
struct in_reg {
	in_reg() : reg_("INVALID_INREG_ACCESS") {}
	in_reg(::temp::temp reg) : reg_(reg) {}

	::temp::temp reg_;
};

struct in_frame {
	in_frame() = delete;
	in_frame(int offt) : offt_(offt) {}

	int offt_;
};

using access = std::variant<in_reg, in_frame>;

inline const ::temp::temp &fp()
{
	static ::temp::temp fp(make_unique("rbp").get());
	return fp;
}

struct frame {
	frame(const symbol &s, const std::vector<bool> &args)
	    : s_(s), escaping_count_(0), reg_count_(0)
	{
		/*
		 * This struct contains a view of where the args should be when
		 * inside the function. The translation for escaping arguments
		 * passed in registers will be done at a later stage.
		 */
		for (size_t i = 0; i < args.size() && i <= 5; i++) {
			formals_.push_back(alloc_local(args[i]));
		}
		for (size_t i = 6; i < args.size(); i++) {
			formals_.push_back(in_frame((i - 6) * 8 + 16));
		}
	}

	access alloc_local(bool escapes)
	{
		if (escapes)
			return in_frame(-(escaping_count_++ * 8 + 8));
		reg_count_++;
		return in_reg(temp::temp());
	}

	const symbol &s_;

	std::vector<access> formals_;
	int escaping_count_;
	size_t reg_count_;
};

inline std::ostream &operator<<(std::ostream &os, const access &a)
{
	if (auto *r = std::get_if<in_reg>(&a))
		return os << "in_reg(" << r->reg_ << ')';
	auto *r = std::get_if<in_frame>(&a);
	if (r->offt_ < 0)
		return os << "in_frame(" << fp() << " - " << -r->offt_ << ")";
	else
		return os << "in_frame(" << fp() << " + " << r->offt_ << ")";
}

inline std::ostream &operator<<(std::ostream &os, const frame &f)
{
	for (auto a : f.formals_)
		os << a << '\n';
	return os;
}
} // namespace frame
