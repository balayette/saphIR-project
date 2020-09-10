#pragma once
#include <vector>

#include "asm-writer/asm-writer.hh"

namespace asm_writer
{
class elf_asm_writer : public asm_writer
{
      public:
	elf_asm_writer(mach::target &target) : asm_writer(target) {}

	virtual void add_string(const utils::label &name,
				const std::string &str) override;

	virtual void add_global(const utils::label &name, size_t size) override;

	virtual void add_init(const symbol &fun) override;

	virtual void add_function(const mach::asm_function &fun) override;
	virtual void
	add_functions(const std::vector<mach::asm_function> &funs) override;

	virtual void to_stream(std::ostream &of) const override;

      private:
	std::vector<std::string> strings_;
	std::vector<std::string> globals_;
	std::vector<std::string> inits_;
	std::vector<std::string> functions_;
};
} // namespace asm_writer
