#include "aarch64-common.hh"

namespace mach::aarch64
{
struct reg {
	utils::temp label;
	std::string repr;
};

reg register_array[] = {
	{make_unique("x0"), "x0"},   {make_unique("x1"), "x1"},
	{make_unique("x2"), "x2"},   {make_unique("x3"), "x3"},
	{make_unique("x4"), "x4"},   {make_unique("x5"), "x5"},
	{make_unique("x6"), "x6"},   {make_unique("x7"), "x7"},
	{make_unique("x8"), "x8"},   {make_unique("x9"), "x9"},
	{make_unique("x10"), "x10"}, {make_unique("x11"), "x11"},
	{make_unique("x12"), "x12"}, {make_unique("x13"), "x13"},
	{make_unique("x14"), "x14"}, {make_unique("x15"), "x15"},
	{make_unique("x16"), "x16"}, {make_unique("x17"), "x17"},
	{make_unique("x18"), "x18"}, {make_unique("x19"), "x19"},
	{make_unique("x20"), "x20"}, {make_unique("x21"), "x21"},
	{make_unique("x22"), "x22"}, {make_unique("x23"), "x23"},
	{make_unique("x24"), "x24"}, {make_unique("x25"), "x25"},
	{make_unique("x26"), "x26"}, {make_unique("x27"), "x27"},
	{make_unique("x28"), "x28"}, {make_unique("fp"), "fp"},
	{make_unique("lr"), "lr"},   {make_unique("sp"), "sp"},
};

std::vector<utils::temp> reg_range(int beg, int end)
{
	std::vector<utils::temp> ret;
	for (int i = beg; i <= end; i++)
		ret.emplace_back(reg_to_temp(static_cast<regs>(i)));
	return ret;
}

utils::temp_set registers()
{
	return utils::temp_set(caller_saved_regs())
	       + utils::temp_set(callee_saved_regs())
	       + utils::temp_set(args_regs());
}

std::vector<utils::temp> caller_saved_regs() { return reg_range(8, 18); }

std::vector<utils::temp> callee_saved_regs() { return reg_range(19, 28); }

std::vector<utils::temp> args_regs() { return reg_range(0, 7); }

std::vector<utils::temp> special_regs()
{
	return {
		reg_to_temp(regs::FP),
		reg_to_temp(regs::LR),
		reg_to_temp(regs::SP),
	};
}

utils::temp fp() { return reg_to_temp(regs::FP); }
utils::temp rv() { return reg_to_temp(regs::R0); }

std::unordered_map<utils::temp, std::string> temp_map()
{
	std::unordered_map<utils::temp, std::string> ret;
	for (unsigned i = 0; i < 32; i++)
		ret.insert({register_array[i].label, register_array[i].repr});
	return ret;
}

std::string register_repr(utils::temp t, unsigned size)
{
	for (unsigned i = 0; i < 32; i++) {
		if (register_array[i].label == t) {
			if (i > 28 || size == 8)
				return register_array[i].repr;
			return std::string("w") + std::to_string(i);
		}
	}

	UNREACHABLE("register not found");
}

utils::temp repr_to_register(std::string repr)
{
	for (size_t i = 0; i < 32; i++) {
		if (register_array[i].repr == repr)
			return register_array[i].label;
	}

	UNREACHABLE("Register does not exist");
}

utils::temp reg_to_temp(regs r) { return register_array[r].label; }
utils::temp reg_to_str(regs r) { return register_array[r].repr; }

} // namespace mach::aarch64
