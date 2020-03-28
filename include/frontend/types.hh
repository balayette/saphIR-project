#pragma once

#include <string>
#include <vector>
#include "utils/assert.hh"
#include "frontend/ops.hh"
#include "utils/symbol.hh"
#include "utils/ref.hh"

namespace types
{
enum class type { INT, STRING, VOID, INVALID };

struct ty {
	virtual ~ty() = default;

	virtual std::string to_string() const = 0;

	// t can be assigned to this
	virtual bool assign_compat(const ty *t) const = 0;

	// return the resulting type if this BINOP t is correctly typed,
	// nullptr otherwise.
	// TODO: This is where implicit type conversions would be handled
	virtual utils::ref<ty> binop_compat(ops::binop binop,
					    const ty *t) const = 0;

	virtual ty *clone() const = 0;

	virtual size_t size() const
	{
		UNREACHABLE("size() on type with no size");
	};
};

bool operator==(const ty *ty, const type &t);
bool operator!=(const ty *ty, const type &t);

struct builtin_ty : public ty {
	builtin_ty();
	builtin_ty(type t, size_t size = 0);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;

	virtual builtin_ty *clone() const override
	{
		return new builtin_ty(ty_, size_);
	}

	size_t size() const override;

	type ty_;

      private:
	size_t size_;
};

struct pointer_ty : public ty {
      private:
	pointer_ty(utils::ref<ty> ty, unsigned ptr);

      public:
	pointer_ty(utils::ref<ty> ty);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;

	virtual pointer_ty *clone() const override
	{
		return new pointer_ty(ty_, ptr_);
	}

	size_t size() const override;
	size_t pointed_size() const;

	utils::ref<ty> ty_;
	unsigned ptr_;
};

utils::ref<builtin_ty> void_type();
// XXX: This should be arch dependant
utils::ref<builtin_ty> integer_type();

bool is_scalar(const ty *ty);
utils::ref<ty> deref_pointer_type(utils::ref<ty> ty);
bool is_integer(const ty *ty);

struct composite_ty : public ty {
};

struct braceinit_ty : public composite_ty {
	braceinit_ty(const std::vector<utils::ref<types::ty>> &types);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;

	virtual braceinit_ty *clone() const override
	{
		return new braceinit_ty(types_);
	}

	std::vector<utils::ref<types::ty>> types_;
};

struct struct_ty : public composite_ty {
	struct_ty(const symbol &name, const std::vector<symbol> &names,
		  const std::vector<utils::ref<types::ty>> &types);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;

	virtual struct_ty *clone() const override
	{
		return new struct_ty(name_, names_, types_);
	}

	std::optional<size_t> member_index(const symbol &name);
	size_t member_offset(const symbol &name);
	utils::ref<ty> member_ty(const symbol &name);

	size_t size() const override;

	std::vector<utils::ref<types::ty>> types_;
	symbol name_;
	std::vector<symbol> names_;

      private:
	size_t size_;
};

struct fun_ty : public ty {
	fun_ty(utils::ref<types::ty> ret_ty,
	       const std::vector<utils::ref<types::ty>> &arg_tys,
	       bool variadic);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;

	virtual fun_ty *clone() const override
	{
		return new fun_ty(ret_ty_, arg_tys_, variadic_);
	}

	utils::ref<types::ty> ret_ty_;
	std::vector<utils::ref<types::ty>> arg_tys_;
	bool variadic_;
};

/*
 * The parser outputs named_ty everywhere a type is used, and they are replaced
 * by pointers to actual types during semantic analysis.
 * This is necessary because of type declarations that the parser doesn't track.
 */
struct named_ty : public ty {
	named_ty(const symbol &name);
	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;

	virtual named_ty *clone() const override { return new named_ty(name_); }

	symbol name_;
};
} // namespace types
