#include "mach/target.hh"

namespace mach
{
static utils::ref<mach::target> curr_target;

std::string target::asm_string(utils::label lab, const std::string &str)
{
	std::string ret(lab.get() + ":\n\t.string \"" + str + "\"\n");
	return ret;
}

size_t target::reg_count() { return registers().size(); }

utils::ref<types::ty> target::invalid_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::INVALID, types::signedness::INVALID, *this);
}

utils::ref<types::ty> target::void_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::VOID, types::signedness::INVALID, *this);
}

utils::ref<types::ty> target::string_type()
{
	return std::make_shared<types::builtin_ty>(
		types::type::STRING, types::signedness::INVALID, *this);
}


frame::frame(target &target, const symbol &s, bool has_return)
    : target_(target), s_(s), leaf_(true), has_return_(has_return)
{
}

asm_function::asm_function(const std::string &prologue,
			   const std::vector<assem::rinstr> &instrs,
			   const std::string &epilogue)
    : prologue_(prologue), instrs_(instrs), epilogue_(epilogue)
{
}

mach::target &TARGET()
{
	ASSERT(curr_target, "Target is not set.");
	return *curr_target;
}

void SET_TARGET(utils::ref<mach::target> target)
{
	ASSERT(!curr_target, "Can't modify the target after it was set.");
	curr_target = target;
}
} // namespace mach
