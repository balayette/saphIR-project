#pragma once

#include "mach/access.hh"

namespace mach::amd64
{
struct reg_acc : public access {
	reg_acc(mach::target &target, utils::temp reg,
		utils::ref<types::ty> &ty);

	ir::tree::rexp exp(size_t offt = 0) const override;
	ir::tree::rexp addr(size_t offt = 0) const override;

	std::ostream &print(std::ostream &os) const override;

	utils::temp reg_;
};

struct frame_acc : public access {
	frame_acc(mach::target &target, utils::temp fp, int offt,
		  utils::ref<types::ty> &ty);

	ir::tree::rexp exp(size_t offt = 0) const override;
	ir::tree::rexp addr(size_t offt = 0) const override;

	std::ostream &print(std::ostream &os) const override;

	utils::temp fp_;
	int offt_;
};

struct global_acc : public access {
	global_acc(mach::target &target, const symbol &name,
		   utils::ref<types::ty> &ty);

	ir::tree::rexp exp(size_t offt = 0) const override;
	ir::tree::rexp addr(size_t offt = 0) const override;

	std::ostream &print(std::ostream &os) const override;

	symbol name_;
};
} // namespace mach::amd64
