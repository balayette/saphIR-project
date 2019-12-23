#pragma once

#include <unordered_set>
#include <vector>

namespace utils
{
template <typename T> class uset : public std::unordered_set<T>
{
      public:
	uset() = default;
	uset(std::vector<T> &elms);

	uset<T> operator+(uset &rhs);
	uset<T> operator-(uset &rhs);
};
} // namespace utils

#include "utils/uset.hxx"
