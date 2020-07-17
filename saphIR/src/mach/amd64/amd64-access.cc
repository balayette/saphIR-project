#include "mach/amd64/amd64-access.hh"
#include "mach/amd64/amd64-common.hh"
#include "mach/target.hh"

namespace mach::amd64
{
reg_acc::reg_acc(mach::target &target, utils::temp reg,
		 utils::ref<types::ty> &ty)
    : access(target, ty), reg_(reg)
{
}

ir::tree::rexp reg_acc::exp(size_t offt) const
{
	ASSERT(offt == 0, "offt must be zero for registers.\n");
	return target_.make_temp(reg_, ty_->clone());
}

ir::tree::rexp reg_acc::addr(size_t) const
{
	UNREACHABLE("Can't take address of value in register.\n");
}

std::ostream &reg_acc::print(std::ostream &os) const
{
	return os << "reg_acc(" << reg_ << ")";
}

frame_acc::frame_acc(mach::target &target, utils::temp fp, int offt,
		     utils::ref<types::ty> &ty)
    : access(target, ty), fp_(fp), offt_(offt)
{
}

ir::tree::rexp frame_acc::exp(size_t offt) const
{
	return target_.make_mem(addr(offt));
}

ir::tree::rexp frame_acc::addr(size_t offt) const
{
	/*
	 * Return a pointer to a variable. If the offset is not 0, then it
	 * doesn't necessarily point to a variable of the same type as ty_.
	 * (addresses of members of structs, for example)
	 */
	auto type = offt ? target_.gpr_type() : ty_->clone();
	type = new types::pointer_ty(type);

	return target_.make_binop(
		ops::binop::PLUS, target_.make_temp(fp_, type),
		target_.make_cnst(offt_ + offt), type->clone());
}

std::ostream &frame_acc::print(std::ostream &os) const
{
	os << "frame_acc(" << fp_ << " ";
	if (offt_ < 0)
		os << "- " << -offt_;
	else
		os << "+ " << offt_;
	return os << ")";
}

global_acc::global_acc(mach::target &target, const symbol &name,
		       utils::ref<types::ty> &ty)
    : access(target, ty), name_(name)
{
}

ir::tree::rexp global_acc::exp(size_t offt) const
{
	return target_.make_mem(addr(offt));
}

// XXX: fix types
ir::tree::rexp global_acc::addr(size_t offt) const
{
	auto type = offt ? target_.gpr_type() : ty_->clone();
	type = new types::pointer_ty(type);

	if (offt != 0)
		return target_.make_binop(
			ops::binop::PLUS, target_.make_name(name_, type),
			target_.make_cnst(offt), type->clone());
	else
		return target_.make_name(name_, type);
}

std::ostream &global_acc::print(std::ostream &os) const
{
	return os << "global_acc(" << name_ << ")";
}
} // namespace mach::amd64
