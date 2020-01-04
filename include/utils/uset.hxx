#pragma once
#include "utils/uset.hh"
#include <algorithm>

namespace utils
{
template <typename T>
uset<T>::uset(std::vector<T> &elms)
    : std::unordered_set<T>(elms.begin(), elms.end())
{
}

template <typename T> uset<T> uset<T>::operator+(const uset &rhs) const
{
	uset<T> ret(*this);
	ret += rhs;
	return ret;
}

template <typename T> uset<T> uset<T>::operator-(const uset &rhs) const
{
	uset<T> ret(*this);
	ret -= rhs;
	return ret;
}

template <typename T> uset<T> &uset<T>::operator+=(const uset &rhs)
{
	this->insert(rhs.begin(), rhs.end());

	return *this;
}

template <typename T> uset<T> &uset<T>::operator-=(const uset &rhs)
{
	for (const auto &v : rhs)
		this->erase(v);

	return *this;
}

template <typename T> uset<T> uset<T>::operator+(T &value) const
{
	uset<T> ret(*this);
	ret += value;
	return ret;
}

template <typename T> uset<T> uset<T>::operator-(T &value) const
{
	uset<T> ret(*this);
	ret -= value;
	return ret;
}

template <typename T> uset<T> &uset<T>::operator+=(const T &value)
{
	this->insert(value);
	return *this;
}

template <typename T> uset<T> &uset<T>::operator-=(const T &value)
{
	this->erase(value);
	return *this;
}

template <typename T> std::vector<T> uset<T>::collect() const
{
	std::vector<T> ret(this->begin(), this->end());
	return ret;
}

template <typename T> uset<T> uset<T>::intersect(const uset<T> &rhs) const
{
	uset<T> ret;

	for (auto &v : rhs) {
		if (this->find(v) != this->end())
			ret += v;
	}

	return ret;
}
} // namespace utils
