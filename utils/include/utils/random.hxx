#pragma once

#include "utils/random.hh"
#include "utils/assert.hh"
#include <random>
#include <iostream>

namespace utils
{
extern thread_local struct xorshift_state state;

template <typename T> T rand(T low, T high)
{
	if (low == high)
		return low;

	uint64_t x = state.a;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	state.a = x;

	uint64_t dist = high - low;
	return (x % dist) + low;
}

template <typename It> It choose(It beg, It end)
{
	if (beg == end)
		return beg;

	auto dist = std::distance(beg, end);
	auto ret = beg;
	std::advance(ret, rand<size_t>(0, dist - 1));
	return ret;
}
} // namespace utils
