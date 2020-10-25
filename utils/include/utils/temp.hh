#pragma once

#include <iostream>
#include <string>
#include <utility>
#include <unordered_map>
#include "utils/symbol.hh"
#include "utils/uset.hh"

namespace utils
{
struct base_temp {
      protected:
	base_temp(const symbol &s) : sym_(s) {}

      public:
	base_temp() = delete;
	const symbol &sym() const { return sym_; }
	const std::string &get() const { return sym_.get(); }
	operator const std::string &() const { return sym_.get(); }

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
	temp(const symbol &s) : base_temp(s) {}
};

struct label : base_temp {
	label() : base_temp(unique_label()) {}
	label(const std::string &s) : base_temp(s) {}
	label(const symbol &s) : base_temp(s) {}
};

inline std::ostream &operator<<(std::ostream &os, const base_temp &t)
{
	return os << t.sym_;
}

using temp_endomap = std::unordered_map<temp, temp>;
using temp_set = utils::uset<temp>;
using temp_pair = std::pair<temp, temp>;
using temp_pair_set = utils::uset<temp_pair>;
} // namespace utils

namespace std
{
template <> struct hash<utils::label> {
	std::size_t operator()(const utils::label &s) const
	{
		return std::hash<symbol>{}(s.sym());
	}
};
template <> struct hash<utils::temp> {
	std::size_t operator()(const utils::temp &t) const
	{
		return std::hash<symbol>{}(t.sym());
	}
};
template <> struct hash<utils::temp_pair> {
	std::size_t operator()(const utils::temp_pair &p) const
	{
		return std::hash<utils::temp>{}(p.first)
		       + std::hash<utils::temp>{}(p.second);
	}
};
} // namespace std
