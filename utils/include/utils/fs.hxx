#pragma once

#include "fs.hh"
#include "utils/assert.hh"
#include <cstring>

namespace utils
{
template <typename Dest>
void mapped_file::read(Dest *dest, size_t offt, size_t num) const
{
	ASSERT(offt + sizeof(Dest) * num <= size_, "Out of bounds read");
	std::memcpy(dest, data_ + offt, sizeof(Dest) * num);
}

template <typename Dest, typename Size> Dest *mapped_file::ptr(Size offt) const
{
	ASSERT(offt + sizeof(Dest) <= size_, "Out of bounds ptr");
	return reinterpret_cast<Dest *>(data_ + offt);
}
} // namespace utils
