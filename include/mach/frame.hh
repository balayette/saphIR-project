#pragma once

#include "utils/symbol.hh"
#include "ir/ir.hh"
#include "frontend/ops.hh"
#include "utils/temp.hh"
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
const ::temp::temp &fp();

const ::temp::temp &rv();

struct access {
	access() = default;
	virtual ~access() = default;
	virtual backend::tree::rexp exp() const = 0;
	virtual std::ostream &print(std::ostream &os) const = 0;
};

struct in_reg : public access {
	in_reg(::temp::temp reg);

	backend::tree::rexp exp() const override;

	std::ostream &print(std::ostream &os) const override;

	::temp::temp reg_;
};

struct in_frame : public access {
	in_frame(int offt);

	backend::tree::rexp exp() const override;

	std::ostream &print(std::ostream &os) const override;

	int offt_;
};

struct frame {
	frame(const symbol &s, const std::vector<bool> &args);

	utils::ref<access> alloc_local(bool escapes);

	backend::tree::rstm proc_entry_exit_1(backend::tree::rstm s,
					      ::temp::label ret_lbl);

	const symbol s_;
	std::vector<utils::ref<access>> formals_;
	int escaping_count_;
	size_t reg_count_;
};

struct fragment {
	fragment() = default;
	virtual ~fragment() = default;
};

struct str_fragment : public fragment {
	str_fragment(::temp::label lab, const std::string &s) : lab_(lab), s_(s)
	{
	}

	::temp::label lab_;
	std::string s_;
};

struct fun_fragment : public fragment {
	fun_fragment(backend::tree::rstm body, frame &frame,
		     ::temp::label ret_lbl)
	    : body_(body), frame_(frame), ret_lbl_(ret_lbl)
	{
	}

	backend::tree::rstm body_;
	frame frame_;
	::temp::label ret_lbl_;
};

std::ostream &operator<<(std::ostream &os, const access &a);

std::ostream &operator<<(std::ostream &os, const frame &f);
} // namespace frame
