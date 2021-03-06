#pragma once

#include "mach/target.hh"

namespace mach::aarch64
{
struct aarch64_frame : public mach::frame {
	aarch64_frame(target &target_, const symbol &s,
		      const std::vector<bool> &args,
		      std::vector<utils::ref<types::ty>> types,
		      bool has_return);

	virtual utils::ref<access>
	alloc_local(bool escapes, utils::ref<types::ty> ty) override;
	virtual utils::ref<access> alloc_local(bool escapes) override;

	virtual ir::tree::rstm prepare_temps(ir::tree::rstm s,
					     utils::label ret_lbl) override;

	virtual void
	add_live_registers(std::vector<assem::rinstr> &instrs) override;
	virtual asm_function
	make_asm_function(std::vector<assem::rinstr> &instrs,
			  utils::label pro_lbl, utils::label epi_lbl) override;

	virtual std::vector<utils::ref<access>> formals() override;

	size_t locals_size_;
	size_t reg_count_;
	utils::ref<access> canary_;

	std::vector<utils::ref<access>> formals_;
};

struct aarch64_target : public mach::target {
	virtual std::string name() override;
	virtual utils::temp_set registers() override;
	virtual std::vector<utils::temp> caller_saved_regs() override;
	virtual std::vector<utils::temp> callee_saved_regs() override;
	virtual std::vector<utils::temp> args_regs() override;
	virtual std::vector<utils::temp> special_regs() override;

	virtual utils::temp fp() override;
	virtual utils::temp rv() override;

	virtual std::unordered_map<utils::temp, std::string>
	temp_map() override;

	virtual std::string register_repr(utils::temp t,
					  unsigned size) override;
	virtual utils::temp repr_to_register(std::string repr) override;

	utils::ref<types::ty>
	integer_type(types::signedness signedness =
			     types::signedness::SIGNED) override;
	virtual utils::ref<types::ty> integer_type(types::signedness signedness,
						   size_t sz) override;
	utils::ref<types::ty> boolean_type() override;
	utils::ref<types::ty> gpr_type() override;

	virtual utils::ref<mach::frame>
	make_frame(const symbol &s, const std::vector<bool> &args,
		   std::vector<utils::ref<types::ty>> types, bool has_return,
		   bool needs_stack_protector) override;

	virtual utils::ref<asm_generator> make_asm_generator() override;
	virtual utils::ref<access>
	alloc_global(const symbol &name, utils::ref<types::ty> &ty) override;
};
} // namespace mach::aarch64
