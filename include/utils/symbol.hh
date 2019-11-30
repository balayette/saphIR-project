#pragma once

#include <iostream>
#include <set>
#include <string>

class symbol
{
      public:
	symbol(const std::string &str);
	symbol(const char *str = "");

	symbol &operator=(const symbol &rhs);
	constexpr symbol(const symbol &) = default; /* Keep g++ & flex happy*/

	bool operator==(const symbol &rhs) const;
	bool operator!=(const symbol &rhs) const;

	size_t size() const;

	friend std::ostream &operator<<(std::ostream &ostr, const symbol &the);

	const std::string &get() const;

      private:
	std::set<std::string> &get_set();
	const std::string *instance_;
};

symbol unique_label();
symbol unique_label(const std::string &s);
symbol unique_temp();

symbol make_unique(const symbol &sym);

namespace std
{
template <> struct hash<symbol> {
	std::size_t operator()(const symbol &s) const
	{
		return std::hash<std::string>{}(s.get());
	}
};
} // namespace std
