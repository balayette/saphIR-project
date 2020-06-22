#include "mach/target.hh"

namespace mach
{
std::string target::asm_string(utils::label lab, const std::string &str)
{
	std::string ret(lab.get() + ":\n\t.string \"" + str + "\"\n");
	return ret;
}

size_t target::reg_count() { return registers().size(); }

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
} // namespace mach
