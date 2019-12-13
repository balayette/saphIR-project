#pragma once

#include "utils/symbol.hh"
#include "ir/ir.hh"
#include "frontend/ops.hh"
#include "utils/temp.hh"
#include "ass/instr.hh"
#include <vector>
#include <variant>

/*
 * x86_64 calling convention:
 * RDI, RSI, RDX, RCX, R8, R9, (R10 = static link), stack (right to left)
 *
 * Callee saved: RBX, RBP, and R12, R13, R14, R15
 * Clobbered: RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11
 *
 * fun f(a, b, c, d, e, f, g, h)
 *
 * fp + 24	-> h
 * fp + 16	-> g
 * fp + 8 	-> ret addr
 * fp		-> saved fp
 * fp + ... 	-> local variables
 */

namespace mach
{
enum regs {
	RAX,
	RBX,
	RCX,
	RDX,
	RSI,
	RDI,
	RSP,
	RBP,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15
};

::temp::temp reg_to_temp(regs r);

::temp::temp reg_to_str(regs r);

::temp::temp fp();

::temp::temp rv();

std::vector<::temp::temp> caller_saved_regs();
std::vector<::temp::temp> callee_saved_regs();
std::vector<::temp::temp> args_regs();
std::vector<::temp::temp> special_regs();

struct access {
	access() = default;
	virtual ~access() = default;
	virtual ir::tree::rexp exp() const = 0;
	virtual std::ostream &print(std::ostream &os) const = 0;
};

struct in_reg : public access {
	in_reg(::temp::temp reg);

	ir::tree::rexp exp() const override;

	std::ostream &print(std::ostream &os) const override;

	::temp::temp reg_;
};

struct in_frame : public access {
	in_frame(int offt);

	ir::tree::rexp exp() const override;

	std::ostream &print(std::ostream &os) const override;

	int offt_;
};

struct frame {
	frame(const symbol &s, const std::vector<bool> &args);

	utils::ref<access> alloc_local(bool escapes);

	ir::tree::rstm proc_entry_exit_1(ir::tree::rstm s,
					 ::temp::label ret_lbl);

	void proc_entry_exit_2(std::vector<assem::instr> &instrs);
	void proc_entry_exit_3(std::vector<assem::instr> &instrs);
	const symbol s_;
	std::vector<utils::ref<access>> formals_;
	int escaping_count_;
	size_t reg_count_;
	::temp::label body_begin_;
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
	fun_fragment(ir::tree::rstm body, frame &frame, ::temp::label ret_lbl)
	    : body_(body), frame_(frame), ret_lbl_(ret_lbl)
	{
	}

	ir::tree::rstm body_;
	frame frame_;
	::temp::label ret_lbl_;
};

std::ostream &operator<<(std::ostream &os, const access &a);

std::ostream &operator<<(std::ostream &os, const frame &f);
} // namespace mach
