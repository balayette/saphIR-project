#pragma once
#include "utils/uset.hh"

namespace utils
{
template <typename T>
uset<T>::uset(std::vector<T> &elms)
    : std::unordered_set<T>(elms.begin(), elms.end())
{
}

template <typename T> uset<T> uset<T>::operator+(uset &rhs) { return rhs; }

template <typename T> uset<T> uset<T>::operator-(uset &rhs) { return rhs; }

} // namespace utils
