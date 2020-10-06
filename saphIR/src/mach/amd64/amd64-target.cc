#include "mach/amd64/amd64-target.hh"
#include "mach/amd64/amd64-access.hh"
#include "mach/amd64/amd64-codegen.hh"
#include "mach/amd64/amd64-common.hh"
#include "utils/misc.hh"

namespace mach::amd64
{
amd64_frame::amd64_frame(target &target, const symbol &s,
			 const std::vector<bool> &args,
			 std::vector<utils::ref<types::ty>> types,
			 bool has_return, bool needs_stack_protector)
    : mach::frame(target, s, has_return),
      locals_size_(needs_stack_protector ? 8 : 0), reg_count_(0),
      canary_(needs_stack_protector ? alloc_local(true) : nullptr),
      needs_stack_protector_(needs_stack_protector)
{
	/*
	 * This struct contains a view of where the args should be when
	 * inside the function. The translation for escaping arguments
	 * passed in registers will be done at a later stage.
	 */
	for (size_t i = 0; i < args.size() && i <= 5; i++)
		formals_.push_back(alloc_local(args[i], types[i]));
	for (size_t i = 6; i < args.size(); i++)
		formals_.push_back(new frame_acc(target_,
						 reg_to_temp(regs::RBP),
						 (i - 6) * 8 + 16, types[i]));
}

utils::ref<access> amd64_frame::alloc_local(bool escapes,
					    utils::ref<types::ty> type)
{
	if (escapes) {
		locals_size_ += type->size();
		return new frame_acc(target_, reg_to_temp(regs::RBP),
				     -locals_size_, type);
	}
	reg_count_++;
	return new reg_acc(target_, utils::temp(), type);
}

utils::ref<access> amd64_frame::alloc_local(bool escapes)
{
	return alloc_local(escapes, target_.integer_type());
}

ir::tree::rstm amd64_frame::prepare_temps(ir::tree::rstm s,
					  utils::label ret_lbl)
{
	auto in_regs = args_regs();
	auto *seq = target_.make_seq({});

	auto callee_saved = callee_saved_regs();
	std::vector<utils::temp> callee_saved_temps(callee_saved.size());
	for (size_t i = 0; i < callee_saved.size(); i++)
		seq->append(target_.make_move(
			target_.make_temp(callee_saved_temps[i],
					  target_.gpr_type()),
			target_.make_temp(callee_saved[i],
					  target_.gpr_type())));

	for (size_t i = 0; i < formals_.size() && i < in_regs.size(); i++) {
		seq->append(target_.make_move(
			formals_[i]->exp(),
			target_.make_temp(in_regs[i],
					  formals_[i]->exp()->ty_)));
	}
	seq->append(s);

	seq->append(target_.make_label(ret_lbl));

	for (size_t i = 0; i < callee_saved.size(); i++) {
		seq->append(target_.make_move(
			target_.make_temp(callee_saved[i], target_.gpr_type()),
			target_.make_temp(callee_saved_temps[i],
					  target_.gpr_type())));
	}

	return seq;
}

void amd64_frame::add_live_registers(std::vector<assem::rinstr> &instrs)
{
	auto spec = special_regs();
	std::vector<assem::temp> live;
	live.insert(live.end(), spec.begin(), spec.end());

	for (auto &r : callee_saved_regs())
		live.push_back(r);
	if (has_return_)
		live.push_back(reg_to_temp(regs::RAX));

	std::string repr("# sink:");
	for (auto &r : live)
		repr += " " + r.temp_.get();
	instrs.push_back(new assem::oper(repr, {}, live, {}));
}

mach::asm_function
amd64_frame::make_asm_function(std::vector<assem::rinstr> &instrs,
			       utils::label body_lbl, utils::label epi_lbl)
{
	std::string prologue(".global ");
	prologue += s_.get() + '\n' + s_.get() + ":\n";
	prologue +=
		"\tpush %rbp\n"
		"\tmov %rsp, %rbp\n";

	size_t stack_space = ROUND_UP(locals_size_, 16);
	// There is no need to update %rsp if we're a leaf function
	// and we need <= 128 bytes of stack space. (System V red zone)
	// Stack accesses could also use %rsp instead of %rbp, and we could
	// remove the prologue.
	if (stack_space > 128 || (stack_space > 0 && !leaf_)) {
		prologue += "\tsub $";
		prologue += std::to_string(stack_space);
		prologue += ", %rsp\n";
	}

	if (needs_stack_protector_) {
		prologue += "\tmovq %fs:40, %r11\n";
		prologue += "\tmovq %r11, -8(%rbp)\n";
		prologue += "\txor %r11, %r11\n";
	}

	prologue += "\tjmp .L_" + body_lbl.get() + '\n';

	std::string epilogue;

	if (needs_stack_protector_) {
		epilogue += "\tmovq -8(%rbp), %r11\n";
		epilogue += "\txorq %fs:40, %r11\n";
		epilogue += "\tje .L_ok_" + epi_lbl.get() + "\n";
		epilogue += "\tcall __stack_chk_fail@PLT\n";
		epilogue += ".L_ok_" + epi_lbl.get() + ":\n";
	}

	epilogue +=
		"\tleave\n"
		"\tret\n";

	return asm_function(prologue, instrs, epilogue);
}

std::vector<utils::ref<access>> amd64_frame::formals() { return formals_; }

std::string amd64_target::name() { return "amd64"; }

utils::temp_set amd64_target::registers() { return mach::amd64::registers(); }

std::vector<utils::temp> amd64_target::caller_saved_regs()
{
	return mach::amd64::caller_saved_regs();
}

std::vector<utils::temp> amd64_target::callee_saved_regs()
{
	return mach::amd64::callee_saved_regs();
}

std::vector<utils::temp> amd64_target::args_regs()
{
	return mach::amd64::args_regs();
}

std::vector<utils::temp> amd64_target::special_regs()
{
	return mach::amd64::special_regs();
}

utils::temp amd64_target::fp() { return mach::amd64::fp(); }
utils::temp amd64_target::rv() { return mach::amd64::rv(); }

std::unordered_map<utils::temp, std::string> amd64_target::temp_map()
{
	return mach::amd64::temp_map();
}

std::string amd64_target::register_repr(utils::temp t, unsigned size)
{
	return mach::amd64::register_repr(t, size);
}

utils::temp amd64_target::repr_to_register(std::string repr)
{
	return mach::amd64::repr_to_register(repr);
}

utils::ref<types::ty> amd64_target::integer_type(types::signedness signedness)
{
	return std::make_shared<types::builtin_ty>(types::type::INT, signedness,
						   *this);
}

utils::ref<types::ty> amd64_target::integer_type(types::signedness signedness,
						 size_t sz)
{
	return std::make_shared<types::builtin_ty>(types::type::INT, sz,
						   signedness, *this);
}

utils::ref<types::ty> amd64_target::boolean_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::INT, 1, types::signedness::UNSIGNED, *this);
}

utils::ref<types::ty> amd64_target::gpr_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::INT, 8, types::signedness::UNSIGNED, *this);
}

utils::ref<asm_generator> amd64_target::make_asm_generator()
{
	return new amd64_generator(*this);
}

utils::ref<mach::frame>
amd64_target::make_frame(const symbol &s, const std::vector<bool> &args,
			 std::vector<utils::ref<types::ty>> types,
			 bool has_return, bool needs_stack_protector)
{
	return new amd64_frame(*this, s, args, types, has_return,
			       needs_stack_protector);
}

utils::ref<access> amd64_target::alloc_global(const symbol &name,
					      utils::ref<types::ty> &ty)
{
	return new global_acc(*this, name, ty);
}
} // namespace mach::amd64
