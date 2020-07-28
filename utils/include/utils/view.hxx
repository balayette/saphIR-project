#pragma once

#include "view.hh"
#include "utils/assert.hh"
#include "fmt/format.h"
#include <sstream>

namespace utils
{
template <typename T> template <typename Idx> T &bufview<T>::operator[](Idx i)
{
	ASSERT(sz_ > i, "Out of bounds access");
	return buf_[i];
}
} // namespace utils
