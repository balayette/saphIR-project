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
