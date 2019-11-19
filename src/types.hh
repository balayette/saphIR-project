#pragma once

#include <string>

namespace types
{

enum class type { INT, STRING, VOID, INVALID };

struct ty {
	ty() : ty_(type::INVALID), ptr_(0) {}
	ty(type t) : ty_(t), ptr_(0) {}
	ty(type t, unsigned ptr) : ty_(t), ptr_(ptr) {}

	std::string to_string() const;

	bool operator==(const type &t) const { return !ptr_ && t == ty_; }

	bool operator!=(const type &t) const { return !(*this == t); }

	bool compatible(const ty &rhs) const
	{
		return ptr_ == rhs.ptr_ && ty_ == rhs.ty_;
	}

	bool compatible(const type t) const { return !ptr_ && ty_ == t; }

	type ty_;
	unsigned ptr_;
};

} // namespace types
