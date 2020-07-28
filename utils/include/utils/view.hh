#pragma once

namespace utils
{
template <typename T> class bufview
{
      public:
	bufview(T *buf, size_t sz) : buf_(buf), sz_(sz) {}

	size_t size() const { return sz_; }

	template <typename Idx> T &operator[](Idx i);
	T *data() const { return buf_; }

	template <typename Add> bufview<T> operator+(Add add) const
	{
		ASSERT(add < sz_, "Out of range view");
		return bufview<T>(buf_ + add, sz_ - add);
	}

      private:
	T *buf_;
	size_t sz_;
};
} // namespace utils

#include "view.hxx"
