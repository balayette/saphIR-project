#pragma once

#include <iostream>
#include <string>
#include "symbol.hh"

namespace temp
{
struct base_temp {
      protected:
	base_temp(const symbol &s) : sym_(s) {}

      public:
	base_temp() = delete;
	symbol sym_;
};

struct temp : base_temp {
	temp() : base_temp(unique_temp()) {}
        temp(const std::string& name) : base_temp(name) {}
};

struct label : base_temp {
	label() : base_temp(unique_label()) {}

	label(const std::string &s) : base_temp(unique_label(s)) {}
};

inline std::ostream &operator<<(std::ostream &os, const base_temp &t)
{
	return os << t.sym_;
}
} // namespace temp
