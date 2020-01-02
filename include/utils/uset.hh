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

	uset<T> operator+(const uset &rhs) const;
	uset<T> operator-(const uset &rhs) const;
};
} // namespace utils

#include "utils/uset.hxx"
