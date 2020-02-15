#include "frontend/types.hh"

namespace types
{
const std::string str[] = {"int", "string", "void", "invalid"};
const unsigned default_size[] = {64, 64, 0, 0};

ty::ty(size_t size, unsigned ptr) : size_(size), ptr_(ptr) {}

builtin_ty::builtin_ty() : ty(0, 0), ty_(type::INVALID) {}
builtin_ty::builtin_ty(type t, size_t size, unsigned ptr)
    : ty(size, ptr), ty_(t)
{
	if (size == 0)
		size_ = default_size[static_cast<unsigned>(t)];
}

std::string builtin_ty::to_string() const
{
	std::string ret(str[static_cast<int>(ty_)]);
	ret += "<" + std::to_string(size_) + ">";
	for (unsigned i = 0; i < ptr_; i++)
		ret += '*';
	return ret;
}

bool builtin_ty::compatible(const type &t) const { return !ptr_ && ty_ == t; }
bool builtin_ty::compatible(const ty *t) const
{
	if (auto bt = dynamic_cast<const builtin_ty *>(t))
		return ptr_ == bt->ptr_ && ty_ == bt->ty_;
	return false;
}

named_ty::named_ty(const symbol &name, unsigned ptr)
    : ty(0, ptr), name_(name)
{
}

std::string named_ty::to_string() const { return name_; }

bool named_ty::compatible(const type &) const { return false; }

bool named_ty::compatible(const ty *) const { return false; }
} // namespace types
