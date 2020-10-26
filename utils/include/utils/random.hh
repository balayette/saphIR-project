#pragma once

#include <cstdint>

namespace utils
{
struct xorshift_state {
	uint64_t a;
};

template <typename T> T rand(T low, T high);
template <typename It> It choose(It beg, It end);

void seed(uint64_t seed);
} // namespace utils

#include "utils/random.hxx"
