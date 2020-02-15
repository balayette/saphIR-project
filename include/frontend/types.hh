#pragma once

#include <string>
#include <vector>
#include "utils/symbol.hh"
#include "utils/ref.hh"

namespace types
{
enum class type { INT, STRING, VOID, INVALID };

struct ty {
	ty(size_t size = 0, unsigned ptr = 0);
	virtual ~ty() = default;

	virtual std::string to_string() const = 0;

	virtual bool compatible(const type &t) const = 0;
	virtual bool compatible(const ty *t) const = 0;

	virtual ty *clone() const = 0;

	size_t size_;
	unsigned ptr_;
};

bool operator==(const ty *ty, const type &t);
bool operator!=(const ty *ty, const type &t);

struct builtin_ty : public ty {
	builtin_ty();
	builtin_ty(type t, size_t size = 0, unsigned ptr = 0);

	std::string to_string() const override;

	bool compatible(const type &t) const override;
	bool compatible(const ty *t) const override;

	virtual builtin_ty *clone() const override
	{
		return new builtin_ty(ty_, size_, ptr_);
	}

      private:
	type ty_;
};

struct braceinit_ty : public ty {
	braceinit_ty(const std::vector<utils::ref<types::ty>> &types);

	std::string to_string() const override;

	bool compatible(const type &t) const override;
	bool compatible(const ty *t) const override;

	virtual braceinit_ty *clone() const override
	{
		return new braceinit_ty(types_);
	}

	std::vector<utils::ref<types::ty>> types_;
};

struct struct_ty : public braceinit_ty {
	struct_ty(const symbol &name,
		  const std::vector<utils::ref<types::ty>> &types,
		  unsigned ptr = 0);

	std::string to_string() const override;

	bool compatible(const type &t) const override;
	bool compatible(const ty *t) const override;

	virtual struct_ty *clone() const override
	{
		return new struct_ty(name_, types_, ptr_);
	}

	symbol name_;
};

/*
 * The parser outputs named_ty everywhere a type is used, and they are replaced
 * by pointers to actual types during semantic analysis.
 * This is necessary because of type declarations that the parser doesn't track.
 */
struct named_ty : public ty {
	named_ty(const symbol &name, unsigned ptr = 0);
	std::string to_string() const override;

	bool compatible(const type &t) const override;
	bool compatible(const ty *t) const override;

	virtual named_ty *clone() const override
	{
		return new named_ty(name_, ptr_);
	}

	symbol name_;
};
} // namespace types
