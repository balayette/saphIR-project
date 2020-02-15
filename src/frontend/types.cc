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

braceinit_ty::braceinit_ty(const std::vector<utils::ref<types::ty>> &types)
    : ty(0, 0), types_(types)
{
	for (auto t : types_)
		size_ += t->size_;
}

std::string braceinit_ty::to_string() const
{
	std::string ret("{");
	for (auto t : types_)
		ret += " " + t->to_string();
	ret += "}";

	return ret;
}

// no brace init of scalars
bool braceinit_ty::compatible(const type &) const { return false; }

bool braceinit_ty::compatible(const ty *t) const
{
	if (auto *st = dynamic_cast<const struct_ty *>(t)) {
		if (st->types_.size() != types_.size())
			return false;

		for (size_t i = 0; i < types_.size(); i++) {
			if (!types_[i]->compatible(&st->types_[i]))
				return false;
		}

		return true;
	}
	return false;
}

struct_ty::struct_ty(const symbol &name, const std::vector<symbol> &names,
		     const std::vector<utils::ref<types::ty>> &types,
		     unsigned ptr)
    : braceinit_ty(types), name_(name), names_(names)
{
	ptr_ = ptr;
	if (ptr_)
		size_ = 8;
	// else, size_ was set by braceinit_ty's constructor
}

std::string struct_ty::to_string() const
{
	std::string ret("struct ");
	ret += name_;

	for (unsigned i = 0; i < ptr_; i++)
		ret += '*';

	return ret;
}

bool struct_ty::compatible(const type &) const { return false; }

bool struct_ty::compatible(const ty *t) const
{
	// struct names are unique in a scope, so this should be enough
	if (auto *st = dynamic_cast<const struct_ty *>(t))
		return st->name_ == name_;

	if (auto *bi = dynamic_cast<const braceinit_ty *>(t)) {
		if (ptr_)
			return false;
		if (bi->types_.size() != types_.size())
			return false;
		for (size_t i = 0; i < types_.size(); i++) {
			if (!types_[i]->compatible(&bi->types_[i]))
				return false;
		}
		return true;
	}
	return false;
}

std::optional<size_t> struct_ty::member_index(const symbol &name)
{
	for (size_t i = 0; i < types_.size(); i++) {
		if (names_[i] == name)
			return i;
	}

	return std::nullopt;
}

size_t struct_ty::member_offset(const symbol &name)
{
	size_t offt = 0;
	for (size_t i = 0; i < types_.size() && names_[i] != name; i++) {
		offt += types_[i]->size_;
	}

	return offt;
}

named_ty::named_ty(const symbol &name, unsigned ptr) : ty(0, ptr), name_(name)
{
}

std::string named_ty::to_string() const { return name_; }

bool named_ty::compatible(const type &) const { return false; }

bool named_ty::compatible(const ty *) const { return false; }

} // namespace types
