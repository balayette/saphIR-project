#pragma once

#include <unordered_set>
#include <vector>
#include <utility>

namespace utils
{
template <typename T> class uset : public std::unordered_set<T>
{
      public:
	uset() = default;
	uset(const std::vector<T> &elms);

	uset<T> operator+(const uset &rhs) const;
	uset<T> operator-(const uset &rhs) const;
	uset<T> &operator+=(const uset &rhs);
	uset<T> &operator-=(const uset &rhs);

	uset<T> operator+(T &value) const;
	uset<T> operator-(T &value) const;
	uset<T> &operator+=(const T &value);
	uset<T> &operator-=(const T &value);

	template <typename It> uset<T> operator+(std::pair<It, It> it) const;
	template <typename It> uset<T> &operator+=(std::pair<It, It> it);

	uset<T> intersect(const uset<T> &rhs) const;

	std::vector<T> collect() const;

	T pop();
};
} // namespace utils

#include "utils/uset.hxx"
