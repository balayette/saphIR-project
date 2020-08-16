#pragma once

#include <string>
#include <vector>
#include "utils/assert.hh"
#include "utils/scoped.hh"
#include "ir/ops.hh"
#include "utils/symbol.hh"
#include "utils/ref.hh"

#define DEFAULT_SIZE (42)

namespace mach
{
struct target;
}

namespace types
{
enum class type { INT, STRING, VOID, INVALID };
enum class signedness { INVALID, SIGNED, UNSIGNED };

struct ty {
	virtual ~ty() = default;
	ty(mach::target &target) : target_(target) {}

	virtual std::string to_string() const = 0;

	// t can be assigned to this
	virtual bool assign_compat(const ty *t) const = 0;

	// this can be cast to t
	virtual bool cast_compat(const ty *) const { return false; }

	// return the resulting type if this BINOP t is correctly typed,
	// nullptr otherwise.
	// TODO: This is where implicit type conversions would be handled
	virtual utils::ref<ty> binop_compat(ops::binop binop,
					    const ty *t) const = 0;

	// return the resulting type if UNARYOP this is correctly typed,
	// nullptr otherwise.
	virtual utils::ref<ty> unaryop_type(ops::unaryop unaryop) const = 0;

	virtual ty *clone() const = 0;

	virtual bool size_modifier(size_t sz) { return sz == DEFAULT_SIZE; }

	virtual size_t size() const
	{
		UNREACHABLE("size() on type " + to_string() + " with no size");
	}

	virtual signedness get_signedness() const
	{
		return signedness::INVALID;
	}

	/*
	 * Structs and arrays have a size which is different from the size
	 * that the codegen uses to manipulate them: they're actually
	 * pointers
	 */
	virtual size_t assem_size() const { return size(); }

	mach::target &target() { return target_; }

      protected:
	mach::target &target_;
};

bool operator==(const ty *ty, const type &t);
bool operator!=(const ty *ty, const type &t);

struct builtin_ty : public ty {
	builtin_ty(mach::target &target);
	builtin_ty(type t, signedness is_signed, mach::target &target);
	builtin_ty(type t, size_t size, signedness is_signed,
		   mach::target &target);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	bool cast_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;
	utils::ref<ty> unaryop_type(ops::unaryop binop) const override;

	virtual builtin_ty *clone() const override
	{
		return new builtin_ty(ty_, size_, size_modif_, is_signed_,
				      target_);
	}

	size_t size() const override;
	bool size_modifier(size_t sz) override;

	type ty_;

	virtual signedness get_signedness() const override
	{
		return is_signed_;
	}

      private:
	builtin_ty(type t, size_t size, size_t size_modif, signedness is_signed,
		   mach::target &target);

	size_t size_;
	size_t size_modif_;
	signedness is_signed_;
};

struct pointer_ty : public ty {
      private:
	pointer_ty(utils::ref<ty> ty, unsigned ptr);

      public:
	pointer_ty(utils::ref<ty> ty);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	bool cast_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;
	utils::ref<ty> unaryop_type(ops::unaryop binop) const override;

	virtual pointer_ty *clone() const override
	{
		return new pointer_ty(ty_, ptr_);
	}

	virtual signedness get_signedness() const override
	{
		return ty_->get_signedness();
	}

	size_t size() const override;
	size_t pointed_size() const;

	utils::ref<ty> ty_;
	unsigned ptr_;
};

bool is_scalar(const ty *ty);
utils::ref<ty> deref_pointer_type(utils::ref<ty> ty);
bool is_integer(const ty *ty);

struct composite_ty : public ty {
	composite_ty(mach::target &target) : ty(target) {}
};

struct array_ty : public composite_ty {
	array_ty(utils::ref<types::ty> type, size_t n);

	std::string to_string() const override;
	size_t size() const override;

	bool assign_compat(const ty *t) const override;
	bool cast_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;
	utils::ref<ty> unaryop_type(ops::unaryop binop) const override;

	virtual array_ty *clone() const override
	{
		return new array_ty(ty_, n_);
	}

	virtual signedness get_signedness() const override
	{
		return signedness::UNSIGNED;
	}

	virtual size_t assem_size() const override { return 8; }

	utils::ref<types::ty> ty_;
	size_t n_;
};

struct braceinit_ty : public composite_ty {
	braceinit_ty(const std::vector<utils::ref<types::ty>> &types);

	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;
	utils::ref<ty> unaryop_type(ops::unaryop binop) const override;

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
	utils::ref<ty> unaryop_type(ops::unaryop binop) const override;

	virtual struct_ty *clone() const override
	{
		return new struct_ty(name_, names_, types_);
	}

	virtual size_t assem_size() const override { return 8; }

	std::optional<size_t> member_index(const symbol &name);
	size_t member_offset(const symbol &name);
	utils::ref<ty> member_ty(const symbol &name);

	size_t size() const override;

	virtual signedness get_signedness() const override
	{
		// structs behave as pointers
		return signedness::UNSIGNED;
	}

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
	utils::ref<ty> unaryop_type(ops::unaryop binop) const override;

	virtual fun_ty *clone() const override
	{
		return new fun_ty(ret_ty_, arg_tys_, variadic_);
	}

	virtual signedness get_signedness() const override
	{
		return signedness::INVALID;
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
	named_ty(const symbol &name, mach::target &target,
		 size_t sz = DEFAULT_SIZE);
	std::string to_string() const override;

	bool assign_compat(const ty *t) const override;
	utils::ref<ty> binop_compat(ops::binop binop,
				    const ty *t) const override;
	utils::ref<ty> unaryop_type(ops::unaryop binop) const override;

	virtual named_ty *clone() const override
	{
		return new named_ty(name_, target_, sz_);
	}
	size_t size() const override;

	symbol name_;

      private:
	int sz_;
};

utils::ref<ty> concretize_type(utils::ref<ty> &t,
			       utils::scoped_map<symbol, utils::ref<ty>> tmap);

utils::ref<fun_ty> normalize_function_pointer(utils::ref<ty> ty);
} // namespace types
