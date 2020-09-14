#include "asm-writer/elf/elf-asm-writer.hh"
#include "fmt/format.h"

namespace asm_writer
{
void elf_asm_writer::add_string(const utils::label &name,
				const std::string &str)
{
	strings_.push_back(
		fmt::format("{}:\n\t.string \"{}\"\n", name.get(), str));
}

void elf_asm_writer::add_global(const utils::label &name, size_t size)
{
	std::string repr;

	repr += fmt::format(".globl {}\n", name.get());
	// XXX: Alignment is not taken into account anywhere
	repr += ".align 8\n";
	repr += fmt::format(".size {}, {}\n", name.get(), size);
	repr += fmt::format("{}:\n", name.get());
	repr += fmt::format(".zero {}\n", size * 4);

	globals_.push_back(repr);
}

void elf_asm_writer::add_init(const symbol &fun)
{
	inits_.push_back(fmt::format("\t.quad {}\n", fun.get()));
}

void elf_asm_writer::add_function(const mach::asm_function &f)
{
	std::string repr;

	repr += f.prologue_;

	for (auto &i : f.instrs_) {
		if (i->repr().size() == 0)
			continue;
		if (!i.as<assem::label>())
			repr += '\t';
		repr += i->to_string([&](utils::temp t, unsigned sz) {
			return target_.register_repr(t, sz);
		}) + '\n';
	}

	repr += f.epilogue_;
	repr += '\n';

	functions_.push_back(repr);
}

void elf_asm_writer::add_functions(const std::vector<mach::asm_function> &funs)
{
	for (const auto &f : funs)
		add_function(f);
}

void elf_asm_writer::to_stream(std::ostream &stream) const
{
	if (strings_.size()) {
		stream << ".section .rodata\n";
		for (const auto &s : strings_)
			stream << s;
	}

	if (globals_.size()) {
		stream << ".data\n";
		for (const auto &s : globals_)
			stream << s;
	}

	if (inits_.size()) {
		stream << ".section .init_array\n";
		for (const auto &s : inits_)
			stream << s;
	}

	if (functions_.size()) {
		stream << ".text\n";
		for (const auto &s : functions_)
			stream << s;
	}
}
} // namespace asm_writer
