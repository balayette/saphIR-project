#include "mach/aarch64/aarch64-target.hh"
#include "mach/aarch64/aarch64-access.hh"
#include "mach/aarch64/aarch64-codegen.hh"
#include "aarch64-common.hh"
#include "utils/misc.hh"

namespace mach::aarch64
{
std::string aarch64_target::name() { return "aarch64"; }

utils::temp_set aarch64_target::registers()
{
	return mach::aarch64::registers();
}

std::vector<utils::temp> aarch64_target::caller_saved_regs()
{
	return mach::aarch64::caller_saved_regs();
}

std::vector<utils::temp> aarch64_target::callee_saved_regs()
{
	return mach::aarch64::callee_saved_regs();
}

std::vector<utils::temp> aarch64_target::args_regs()
{
	return mach::aarch64::args_regs();
}

std::vector<utils::temp> aarch64_target::special_regs()
{
	return mach::aarch64::special_regs();
}

utils::temp aarch64_target::fp() { return mach::aarch64::fp(); }
utils::temp aarch64_target::rv() { return mach::aarch64::rv(); }

std::unordered_map<utils::temp, std::string> aarch64_target::temp_map()
{
	return mach::aarch64::temp_map();
}

std::string aarch64_target::register_repr(utils::temp t, unsigned size)
{
	return mach::aarch64::register_repr(t, size);
}

utils::temp aarch64_target::repr_to_register(std::string repr)
{
	return mach::aarch64::repr_to_register(repr);
}

utils::ref<types::ty> aarch64_target::integer_type(types::signedness signedness)
{
	return std::make_shared<types::builtin_ty>(types::type::INT, signedness,
						   *this);
}

utils::ref<types::ty> aarch64_target::boolean_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::INT, 1, types::signedness::UNSIGNED, *this);
}

utils::ref<types::ty> aarch64_target::gpr_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::INT, 8, types::signedness::UNSIGNED, *this);
}

utils::ref<asm_generator> aarch64_target::make_asm_generator()
{
	return new aarch64_generator(*this);
}

utils::ref<mach::frame>
aarch64_target::make_frame(const symbol &s, const std::vector<bool> &args,
			   std::vector<utils::ref<types::ty>> types,
			   bool has_return)
{
	return new aarch64_frame(*this, s, args, types, has_return);
}

utils::ref<access> aarch64_target::alloc_global(const symbol &name,
						utils::ref<types::ty> &ty)
{
	return new global_acc(name, ty);
}

aarch64_frame::aarch64_frame(target &target, const symbol &s,
			     const std::vector<bool> &args,
			     std::vector<utils::ref<types::ty>> types,
			     bool has_return)
    : mach::frame(target, s, has_return), locals_size_(0), reg_count_(0)
{
	for (size_t i = 0; i < args.size() && i < 8; i++)
		formals_.push_back(alloc_local(args[i], types[i]));
	for (size_t i = 8; i < args.size(); i++)
		formals_.push_back(new frame_acc(reg_to_temp(regs::FP),
						 (i - 8) * 8 + 16, types[i]));
}

utils::ref<access> aarch64_frame::alloc_local(bool escapes,
					      utils::ref<types::ty> type)
{
	if (escapes) {
		locals_size_ += type->size();
		return new frame_acc(reg_to_temp(regs::FP), -locals_size_,
				     type);
	}

	reg_count_++;
	return new reg_acc(utils::temp(), type);
}

utils::ref<access> aarch64_frame::alloc_local(bool escapes)
{
	return alloc_local(escapes, target_.integer_type());
}

ir::tree::rstm aarch64_frame::proc_entry_exit_1(ir::tree::rstm s,
						utils::label ret_lbl)
{
	auto in_regs = args_regs();
	auto *seq = new ir::tree::seq({});

	auto callee_saved = callee_saved_regs();
	std::vector<utils::temp> callee_saved_temps(callee_saved.size());
	for (size_t i = 0; i < callee_saved.size(); i++)
		seq->children_.push_back(new ir::tree::move(
			new ir::tree::temp(callee_saved_temps[i],
					   target_.gpr_type()),
			new ir::tree::temp(callee_saved[i],
					   target_.gpr_type())));

	for (size_t i = 0; i < formals_.size() && i < in_regs.size(); i++) {
		seq->children_.push_back(new ir::tree::move(
			formals_[i]->exp(),
			new ir::tree::temp(in_regs[i],
					   formals_[i]->exp()->ty_)));
	}

	seq->children_.push_back(s);

	auto *ret = new ir::tree::label(ret_lbl);
	seq->children_.push_back(ret);

	for (size_t i = 0; i < callee_saved.size(); i++) {
		seq->children_.push_back(new ir::tree::move(
			new ir::tree::temp(callee_saved[i], target_.gpr_type()),
			new ir::tree::temp(callee_saved_temps[i],
					   target_.gpr_type())));
	}

	return seq;
}

void aarch64_frame::proc_entry_exit_2(std::vector<assem::rinstr> &instrs)
{
	auto spec = special_regs();
	std::vector<assem::temp> live;
	live.insert(live.end(), spec.begin(), spec.end());

	for (auto &r : callee_saved_regs())
		live.push_back(r);
	if (has_return_)
		live.push_back(reg_to_temp(regs::R0));

	std::string repr("# sink:");
	for (auto &r : live)
		repr += " " + r.temp_.get();
	instrs.push_back(new assem::oper(repr, {}, live, {}));
}

mach::asm_function
aarch64_frame::proc_entry_exit_3(std::vector<assem::rinstr> &instrs,
				 utils::label body_lbl, utils::label epi_lbl)
{
	(void)epi_lbl;

	std::string prologue(".global ");
	prologue += s_.get() + '\n' + s_.get() + ":\n";
	prologue +=
		"\tstp fp, lr, [sp, #-16]!\n"
		"\tmov fp, sp\n";

	size_t stack_space = ROUND_UP(locals_size_, 16);
	if (stack_space != 0) {
		prologue += "\tsub sp, sp, #";
		prologue += std::to_string(stack_space);
		prologue += "\n";
	}
	prologue += "\tb .L_" + body_lbl.get() + '\n';

	std::string epilogue;
	if (stack_space != 0) {
		epilogue += "\tadd sp, sp, #";
		epilogue += std::to_string(stack_space);
		epilogue += "\n";
	}
	epilogue += "\tldp fp, lr, [sp], #16\n";
	epilogue += "\tret\n";

	return asm_function(prologue, instrs, epilogue);
}

std::vector<utils::ref<access>> aarch64_frame::formals() { return formals_; }
} // namespace mach::aarch64
