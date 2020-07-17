#pragma once

#include "ir/ir.hh"
#include "ir/types.hh"
#include <iostream>

namespace mach
{
struct target;

struct access {
	access(mach::target &target, utils::ref<types::ty> &ty);
	virtual ~access() = default;

	// Expression that returns the value/address of the variable represented
	// by the access, plus an offset (useful in the case of structs, to get
	// the value/address of members).
	// The offset must be zero when the access is not stored in memory, and
	// it is impossible to take the address of a register.
	virtual ir::tree::rexp exp(size_t offt = 0) const = 0;
	virtual ir::tree::rexp addr(size_t offt = 0) const = 0;

	virtual std::ostream &print(std::ostream &os) const = 0;

	mach::target &target_;
	utils::ref<types::ty> ty_;
};

std::ostream &operator<<(std::ostream &os, const access &a);
} // namespace mach
