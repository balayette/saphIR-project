#pragma once

#include "symbol.hh"
#include "ir.hh"
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
inline const ::temp::temp &fp()
{
	static ::temp::temp fp(make_unique("rbp").get());
	return fp;
}

inline const ::temp::temp &rv()
{
	static ::temp::temp rax(make_unique("rax").get());
	return rax;
}

struct access {
	access() = default;
	virtual ~access() = default;
	virtual backend::tree::rexp exp() const = 0;
	virtual std::ostream &print(std::ostream &os) const = 0;
};

struct in_reg : public access {
	in_reg() : reg_("INVALID_INREG_ACCESS") {}
	in_reg(::temp::temp reg) : reg_(reg) {}

	backend::tree::rexp exp() const override
	{
		return new backend::tree::temp(reg_);
	}

	std::ostream &print(std::ostream &os) const override
	{
		return os << "in_reg(" << reg_ << ")";
	}

	::temp::temp reg_;
};

struct in_frame : public access {
	in_frame() = delete;
	in_frame(int offt) : offt_(offt) {}

	backend::tree::rexp exp() const override
	{
		return new backend::tree::mem(new backend::tree::binop(
			frontend::binop::PLUS, new backend::tree::temp(fp()),
			new backend::tree::cnst(offt_)));
	}


	std::ostream &print(std::ostream &os) const override
	{
		os << "in_frame(" << fp() << " ";
		if (offt_ < 0)
			os << "- " << -offt_;
		else
			os << "+ " << offt_;
		return os << ")";
	}

	int offt_;
};

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
			formals_.push_back(new in_frame((i - 6) * 8 + 16));
		}
	}

	utils::ref<access> alloc_local(bool escapes)
	{
		if (escapes)
			return new in_frame(-(escaping_count_++ * 8 + 8));
		reg_count_++;
		return new in_reg(temp::temp());
	}

	const symbol s_;
	std::vector<utils::ref<access>> formals_;
	int escaping_count_;
	size_t reg_count_;
};

inline std::ostream &operator<<(std::ostream &os, const access &a)
{
	return a.print(os);
}

inline std::ostream &operator<<(std::ostream &os, const frame &f)
{
	for (auto a : f.formals_)
		os << a << '\n';
	return os;
}
} // namespace frame
