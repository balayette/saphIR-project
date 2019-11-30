#pragma once

#include "ref.hh"

namespace utils
{
template <typename T> ref<T>::ref(T *ptr) : std::shared_ptr<T>(ptr) {}

template <typename T> bool ref<T>::operator==(const T *rhs)
{
	return std::shared_ptr<T>::get() == rhs;
}

template <typename T> bool ref<T>::operator!=(const T *rhs)
{
	return !(*this == rhs);
}

template <typename T>
inline std::ostream &operator<<(std::ostream &os, const ref<T> &p)
{
	return os << *p;
}
} // namespace utils
