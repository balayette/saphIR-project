#pragma once

#include <memory>

namespace utils
{
/* Add implicit constructor to shared_ptr, and equality comparison with T* */
template <typename T> class ref : public std::shared_ptr<T>
{
	using element_type = T;

      public:
	ref(T *ptr = nullptr);
	bool operator==(const T *rhs);
	bool operator!=(const T *rhs);
};

template <typename T>
std::ostream &operator<<(std::ostream &os, const ref<T> &p);
} // namespace utils

#include "ref.hxx"
