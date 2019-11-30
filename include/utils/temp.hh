#pragma once

#include <iostream>
#include <string>
#include "utils/symbol.hh"

namespace temp
{
struct base_temp {
      protected:
	base_temp(const symbol &s) : sym_(s) {}

      public:
	base_temp() = delete;
	bool operator==(const base_temp &rhs) const { return sym_ == rhs.sym_; }
	bool operator!=(const base_temp &rhs) const
	{
		return !(sym_ == rhs.sym_);
	}
	symbol sym_;
};

struct temp : base_temp {
	temp() : base_temp(unique_temp()) {}
	temp(const std::string &name) : base_temp(name) {}
};

struct label : base_temp {
	label() : base_temp(unique_label()) {}
	label(const std::string &s) : base_temp(s) {}
};

inline std::ostream &operator<<(std::ostream &os, const base_temp &t)
{
	return os << t.sym_;
}

} // namespace temp

namespace std
{
template <> struct hash<temp::label> {
	std::size_t operator()(const temp::label &s) const
	{
		return std::hash<std::string>{}(s.sym_.get());
	}
};
} // namespace std
