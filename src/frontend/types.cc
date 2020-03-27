#include "frontend/types.hh"

namespace types
{
const std::string str[] = {"int", "string", "void", "invalid"};
const unsigned default_size[] = {8, 8, 0, 0};

utils::ref<builtin_ty> integer_type()
{
	static auto t = std::make_shared<builtin_ty>(type::INT, 8, 0);

	return t;
}

utils::ref<builtin_ty> void_type()
{
	static auto t = std::make_shared<builtin_ty>(type::VOID, 0, 0);

	return t;
}

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
	if (dynamic_cast<const fun_ty *>(t))
		return t->compatible(this);
	if (auto bt = dynamic_cast<const builtin_ty *>(t))
		return ptr_ == bt->ptr_ && ty_ == bt->ty_;
	return false;
}

braceinit_ty::braceinit_ty(const std::vector<utils::ref<types::ty>> &types)
    : types_(types)
{
	for (auto t : types_)
		size_ += t->size_;
}

std::string braceinit_ty::to_string() const
{
	std::string ret("{");
	for (size_t i = 0; i < types_.size(); i++) {
		ret += types_[i]->to_string();
		if (i != types_.size() - 1)
			ret += ", ";
	}
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
    : types_(types), name_(name), names_(names)
{
	ptr_ = ptr;

	// XXX: Arch specific pointer size
	if (ptr_)
		size_ = 8;
	else {
		for (auto t : types_)
			size_ += t->size_;
	}
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

utils::ref<ty> struct_ty::member_ty(const symbol &name)
{
	auto idx = member_index(name);
	if (idx == std::nullopt)
		return nullptr;
	return types_[*idx];
}

fun_ty::fun_ty(utils::ref<types::ty> ret_ty,
	       const std::vector<utils::ref<types::ty>> &arg_tys, bool variadic)
    : ret_ty_(ret_ty), arg_tys_(arg_tys), variadic_(variadic)
{
}

std::string fun_ty::to_string() const
{
	std::string ret("(");
	for (unsigned i = 0; i < arg_tys_.size(); i++) {
		ret += arg_tys_[i]->to_string();
		if (i != arg_tys_.size() - 1 || variadic_)
			ret += ", ";
	}
	if (variadic_)
		ret += "...";
	ret += ") -> ";

	ret += ret_ty_->to_string();

	return ret;
}

// XXX: There are no function pointer variables, so compatible only checks
// if t is compatible with the return type of the function.
// This needs to change if we want to support function pointers.
bool fun_ty::compatible(const type &t) const { return ret_ty_->compatible(t); }

bool fun_ty::compatible(const ty *t) const { return ret_ty_->compatible(t); }

named_ty::named_ty(const symbol &name, unsigned ptr) : ty(0, ptr), name_(name)
{
}

std::string named_ty::to_string() const { return name_; }

bool named_ty::compatible(const type &) const { return false; }

bool named_ty::compatible(const ty *) const { return false; }

} // namespace types
