#pragma once

#include <memory>

namespace utils
{
/* Add implicit constructor to shared_ptr, and equality comparison with T* */
template <typename T> class ref : public std::shared_ptr<T>
{
      public:
	ref(T *ptr = nullptr) : std::shared_ptr<T>(ptr) {}
	bool operator==(const T *rhs)
	{
		return std::shared_ptr<T>::get() == rhs;
	}
	bool operator!=(const T *rhs) { return !(*this == rhs); }
};

template <typename T>
inline std::ostream &operator<<(std::ostream &os, const ref<T> &p)
{
	return os << *p;
}
} // namespace utils
