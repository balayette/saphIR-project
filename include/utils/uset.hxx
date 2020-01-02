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
        ret.insert(rhs.begin(), rhs.end());
	return ret;
}

template <typename T> uset<T> uset<T>::operator-(const uset &rhs) const
{
        uset<T> ret(*this);

        for (const auto &v: rhs)
                ret.erase(v);

        return ret;
}
} // namespace utils
