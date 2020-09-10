#pragma once

#include <string>
#include <unordered_map>
#include <iostream>

#include "mach/target.hh"
#include "utils/temp.hh"

namespace asm_writer
{
class asm_writer
{
      public:
	asm_writer(mach::target &target) : target_(target) {}

	virtual ~asm_writer() = default;

	virtual void add_string(const utils::label &name,
				const std::string &str) = 0;
	virtual void
	add_strings(const std::unordered_map<utils::label, std::string> &strs);

	virtual void add_global(const utils::label &name, size_t size) = 0;

	virtual void add_init(const symbol &fun) = 0;

	virtual void add_function(const mach::asm_function &fun) = 0;
	virtual void
	add_functions(const std::vector<mach::asm_function> &funs) = 0;

	virtual void to_stream(std::ostream &stream) const = 0;
	virtual std::string str() const;

      protected:
	mach::target &target_;
};
} // namespace asm_writer
