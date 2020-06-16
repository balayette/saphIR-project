#include "frontend/types.hh"
#include "utils/assert.hh"
#include "utils/misc.hh"

namespace types
{
const std::string str[] = {"int", "string", "void", "invalid"};
const unsigned default_size[] = {8, 8, 0, 0};

utils::ref<builtin_ty> integer_type()
{
	return std::make_shared<builtin_ty>(type::INT, signedness::SIGNED);
}

utils::ref<builtin_ty> boolean_type()
{
	return std::make_shared<builtin_ty>(type::INT, 1, signedness::UNSIGNED);
}

utils::ref<builtin_ty> void_type()
{
	return std::make_shared<builtin_ty>(type::VOID, signedness::INVALID);
}

bool is_scalar(const ty *ty)
{
	if (dynamic_cast<const pointer_ty *>(ty))
		return true;

	return dynamic_cast<const composite_ty *>(ty) == nullptr;
}

bool is_integer(const ty *ty)
{
	if (auto bt = dynamic_cast<const builtin_ty *>(ty))
		return bt->ty_ == type::INT;
	return false;
}

utils::ref<ty> deref_pointer_type(utils::ref<ty> ty)
{
	auto pt = ty.as<pointer_ty>();
	auto at = ty.as<array_ty>();
	ASSERT(pt || at, "Trying to dereference non pointer or array");

	if (at)
		return at->ty_->clone();

	if (pt->ptr_ == 1)
		return pt->ty_->clone();

	auto ret = pt->clone();
	ret->ptr_--;
	return ret;
}

builtin_ty::builtin_ty() : ty_(type::INVALID), is_signed_(signedness::INVALID)
{
}
builtin_ty::builtin_ty(type t, signedness is_signed)
    : builtin_ty(t, DEFAULT_SIZE, is_signed)
{
}
builtin_ty::builtin_ty(type t, size_t size, signedness is_signed)
    : ty_(t), size_modif_(DEFAULT_SIZE), is_signed_(is_signed)
{
	if (size == DEFAULT_SIZE)
		size_ = default_size[static_cast<unsigned>(t)];
	else
		size_ = size;
}
builtin_ty::builtin_ty(type t, size_t size, size_t size_modif,
		       signedness is_signed)
    : ty_(t), size_(size), size_modif_(size_modif), is_signed_(is_signed)
{
}

bool builtin_ty::size_modifier(size_t sz)
{
	if (sz == DEFAULT_SIZE)
		return true;

	if (ty_ != type::INT)
		return false;

	if (sz > 8 || sz == 0)
		return false;

	if (!IS_POWER_OF_TWO(sz))
		return false;

	std::cout << "size modif ok, new size " << sz << '\n';
	size_modif_ = sz;
	return true;
}

std::string builtin_ty::to_string() const
{
	std::string ret(str[static_cast<int>(ty_)]);
	if (size_modif_ != DEFAULT_SIZE)
		ret += "<" + std::to_string(size_modif_) + ">";
	return ret;
}

size_t builtin_ty::size() const
{
	return size_modif_ == DEFAULT_SIZE ? size_ : size_modif_;
}

bool builtin_ty::assign_compat(const ty *t) const
{
	if (auto ft = dynamic_cast<const fun_ty *>(t))
		return ft->ret_ty_->assign_compat(this);
	if (auto bt = dynamic_cast<const builtin_ty *>(t))
		return ty_ == bt->ty_;
	return false;
}

/*
 * + and - can be applied to int and pointer type
 * In other cases, the rules are the same as for assignment
 */
utils::ref<ty> builtin_ty::binop_compat(ops::binop op, const ty *t) const
{
	// no operations on strings
	if (ty_ == type::STRING)
		return nullptr;

	if (op != ops::binop::MINUS && op != ops::binop::PLUS) {
		if (!assign_compat(t))
			return nullptr;

		// TODO: Implicit conversions
		return this->clone();
	}

	// if assign_compat, then not special cases for + and -
	if (assign_compat(t))
		return this->clone();

	auto pt = dynamic_cast<const pointer_ty *>(t);
	if (pt && ty_ == type::INT)
		return pt->clone();

	return nullptr;
}

utils::ref<ty> builtin_ty::unaryop_type(ops::unaryop unaryop) const
{
	if (ty_ != type::INT)
		return nullptr;

	switch (unaryop) {
	case ops::unaryop::NOT:
		return boolean_type();
	case ops::unaryop::NEG:
		return this->clone();
	default:
		return nullptr;
	}
}

pointer_ty::pointer_ty(utils::ref<ty> ty, unsigned ptr) : ty_(ty), ptr_(ptr) {}

pointer_ty::pointer_ty(utils::ref<ty> ty)
{
	if (auto pt = ty.as<pointer_ty>()) {
		ty_ = pt->ty_;
		ptr_ = pt->ptr_ + 1;
	} else {
		ty_ = ty;
		ptr_ = 1;
	}
}

std::string pointer_ty::to_string() const
{
	auto ret = ty_->to_string();
	for (unsigned i = 0; i < ptr_; i++)
		ret += '*';
	return ret;
}

size_t pointer_ty::size() const { return 8; }

bool pointer_ty::assign_compat(const ty *t) const
{
	if (auto pt = dynamic_cast<const pointer_ty *>(t))
		return ptr_ == pt->ptr_ && ty_->assign_compat(&pt->ty_);
	if (auto at = dynamic_cast<const array_ty *>(t))
		return ptr_ == 1 && ty_->assign_compat(&at->ty_);

	return false;
}

utils::ref<ty> pointer_ty::binop_compat(ops::binop op, const ty *t) const
{
	if (op != ops::binop::PLUS && op != ops::binop::MINUS)
		return nullptr;

	auto bt = dynamic_cast<const builtin_ty *>(t);
	if (!bt)
		return nullptr;

	if (bt->ty_ != type::INT)
		return nullptr;

	return this->clone();
}

utils::ref<ty> pointer_ty::unaryop_type(ops::unaryop unaryop) const
{
	switch (unaryop) {
	case ops::unaryop::NOT:
		return boolean_type();
	default:
		return nullptr;
	}
}

size_t pointer_ty::pointed_size() const
{
	if (ptr_ > 1)
		return 8;

	return ty_->size();
}

braceinit_ty::braceinit_ty(const std::vector<utils::ref<types::ty>> &types)
    : types_(types)
{
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
bool braceinit_ty::assign_compat(const ty *t) const
{
	if (auto *st = dynamic_cast<const struct_ty *>(t)) {
		if (st->types_.size() != types_.size())
			return false;

		for (size_t i = 0; i < types_.size(); i++) {
			if (!types_[i]->assign_compat(&st->types_[i]))
				return false;
		}

		return true;
	}

	return false;
}

utils::ref<ty> braceinit_ty::binop_compat(ops::binop, const ty *) const
{
	return nullptr;
}

utils::ref<ty> braceinit_ty::unaryop_type(ops::unaryop) const
{
	return nullptr;
}

struct_ty::struct_ty(const symbol &name, const std::vector<symbol> &names,
		     const std::vector<utils::ref<types::ty>> &types)
    : types_(types), name_(name), names_(names)
{
	size_ = 0;
	// XXX: Arch specific pointer size
	for (auto t : types_)
		size_ += t->size();
}

size_t struct_ty::size() const { return size_; }

std::string struct_ty::to_string() const
{
	std::string ret("struct ");
	ret += name_;
	return ret;
}

bool struct_ty::assign_compat(const ty *t) const
{
	// struct names are unique in a scope, so this should be enough
	if (auto *st = dynamic_cast<const struct_ty *>(t))
		return st->name_ == name_;

	if (auto *bi = dynamic_cast<const braceinit_ty *>(t)) {
		if (bi->types_.size() != types_.size())
			return false;
		for (size_t i = 0; i < types_.size(); i++) {
			if (!types_[i]->assign_compat(&bi->types_[i]))
				return false;
		}
		return true;
	}
	return false;
}

utils::ref<ty> struct_ty::binop_compat(ops::binop, const ty *) const
{
	return nullptr;
}

utils::ref<ty> struct_ty::unaryop_type(ops::unaryop) const { return nullptr; }

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
		offt += types_[i]->size();
	}

	return offt;
}

array_ty::array_ty(utils::ref<types::ty> type, size_t n) : ty_(type), n_(n) {}

std::string array_ty::to_string() const
{
	return ty_->to_string() + "[" + std::to_string(n_) + "]";
}

bool array_ty::assign_compat(const ty *t) const
{
	// Can assign a braceinit, if it has the same number of fields, and
	// if all the types are compatible with ty_
	auto bit = dynamic_cast<const braceinit_ty *>(t);
	if (bit) {
		if (bit->types_.size() != n_)
			return false;
		for (auto rhs : bit->types_) {
			if (!ty_->assign_compat(&rhs))
				return false;
		}

		return true;
	}

	// Can assign an array if it is the same size, and the types are
	// compatible
	auto at = dynamic_cast<const array_ty *>(t);
	return at && n_ == at->n_ && ty_->assign_compat(&at->ty_);
}

// no binops on arrays
utils::ref<ty> array_ty::binop_compat(ops::binop, const ty *) const
{
	return nullptr;
}

utils::ref<ty> array_ty::unaryop_type(ops::unaryop unaryop) const
{
	switch (unaryop) {
	case ops::unaryop::NOT:
		return integer_type()->clone();
	default:
		return nullptr;
	}
}

size_t array_ty::size() const { return n_ * ty_->size(); }

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

bool fun_ty::assign_compat(const ty *) const { return false; }
utils::ref<ty> fun_ty::binop_compat(ops::binop, const ty *) const
{
	return nullptr;
}

utils::ref<ty> fun_ty::unaryop_type(ops::unaryop) const { return nullptr; }

named_ty::named_ty(const symbol &name, size_t sz) : name_(name), sz_(sz) {}

std::string named_ty::to_string() const
{
	std::string repr(name_.get() + "_NAMED");
	if (sz_ != DEFAULT_SIZE)
		repr += "<" + std::to_string(sz_) + ">";
	return repr;
}

bool named_ty::assign_compat(const ty *) const { return false; }
utils::ref<ty> named_ty::binop_compat(ops::binop, const ty *) const
{
	return nullptr;
}

utils::ref<ty> named_ty::unaryop_type(ops::unaryop) const { return nullptr; }

size_t named_ty::size() const { return sz_; }
} // namespace types
