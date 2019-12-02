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

	template <typename Derived> ref(const ref<Derived> &rhs);
	template <typename Derived> ref(const std::shared_ptr<Derived> &rhs);

	bool operator==(const T *rhs);
	bool operator!=(const T *rhs);

	template <typename U> ref<U> as();
};

template <typename T>
std::ostream &operator<<(std::ostream &os, const ref<T> &p);
} // namespace utils

#include "ref.hxx"
