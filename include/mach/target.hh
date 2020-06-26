#pragma once

#include "utils/symbol.hh"
#include "utils/temp.hh"
#include "frontend/types.hh"
#include "mach/access.hh"
#include "mach/codegen.hh"

namespace mach
{
struct asm_function {
	asm_function(const std::string &prologue,
		     const std::vector<assem::rinstr> &instrs,
		     const std::string &epilogue);
	const std::string prologue_;
	std::vector<assem::rinstr> instrs_;
	const std::string epilogue_;
};

struct target;

struct frame {
      protected:
	frame(target &target, const symbol &s, bool has_return);

      public:
	virtual ~frame() = default;
	virtual utils::ref<access> alloc_local(bool escapes,
					       utils::ref<types::ty> ty) = 0;
	virtual utils::ref<access> alloc_local(bool escapes) = 0;

	virtual ir::tree::rstm proc_entry_exit_1(ir::tree::rstm s,
						 utils::label ret_lbl) = 0;

	virtual void proc_entry_exit_2(std::vector<assem::rinstr> &instrs) = 0;

	virtual asm_function
	proc_entry_exit_3(std::vector<assem::rinstr> &instrs,
			  utils::label pro_lbl, utils::label epi_lbl) = 0;

	virtual std::vector<utils::ref<access>> formals() = 0;

	target &target_;

	const symbol s_;
	// Defaults to true, overidden by frontend::sema::frame_visitor
	bool leaf_;
	bool has_return_;
};

struct fragment {
	fragment() = default;
	virtual ~fragment() = default;
};

struct str_fragment : public fragment {
	str_fragment(utils::label lab, const std::string &s) : lab_(lab), s_(s)
	{
	}

	utils::label lab_;
	std::string s_;
};

struct fun_fragment : public fragment {
	fun_fragment(ir::tree::rstm body, utils::ref<frame> frame,
		     utils::label ret_lbl, utils::label epi_lbl)
	    : body_(body), frame_(frame), ret_lbl_(ret_lbl), epi_lbl_(epi_lbl)
	{
	}

	ir::tree::rstm body_;
	utils::ref<frame> frame_;
	utils::label ret_lbl_;
	utils::label body_lbl_;
	utils::label epi_lbl_;
};

struct target {
	virtual ~target() = default;

	virtual std::string name() = 0;
	virtual size_t reg_count();

	virtual utils::temp_set registers() = 0;
	virtual std::vector<utils::temp> caller_saved_regs() = 0;
	virtual std::vector<utils::temp> callee_saved_regs() = 0;
	virtual std::vector<utils::temp> args_regs() = 0;
	virtual std::vector<utils::temp> special_regs() = 0;

	virtual utils::temp fp() = 0;
	virtual utils::temp rv() = 0;

	virtual std::unordered_map<utils::temp, std::string> temp_map() = 0;

	virtual std::string register_repr(utils::temp t, unsigned size) = 0;
	virtual utils::temp repr_to_register(std::string repr) = 0;

	virtual utils::ref<types::ty> invalid_type();
	virtual utils::ref<types::ty> void_type();
	virtual utils::ref<types::ty> string_type();
	virtual utils::ref<types::ty> integer_type(
		types::signedness signedness = types::signedness::SIGNED) = 0;
	virtual utils::ref<types::ty> boolean_type() = 0;
	virtual utils::ref<types::ty> gpr_type() = 0;

	virtual utils::ref<frame>
	make_frame(const symbol &s, const std::vector<bool> &args,
		   std::vector<utils::ref<types::ty>> types,
		   bool has_return) = 0;

	virtual utils::ref<asm_generator> make_asm_generator() = 0;

	virtual utils::ref<access> alloc_global(const symbol &name,
						utils::ref<types::ty> &ty) = 0;

	virtual std::string asm_string(utils::label lab,
				       const std::string &str);
};

mach::target &TARGET();
void SET_TARGET(utils::ref<mach::target> target);
} // namespace mach
