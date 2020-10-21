#pragma once

#include "utils/random.hh"
#include "utils/assert.hh"
#include <random>
#include <iostream>

namespace utils
{
template <typename T> T rand(T low, T high)
{
	static std::mt19937 gen(1);

	std::uniform_int_distribution<T> dis(low, high);

	ASSERT(low <= high, "Incorrect range");

	auto ret = dis(gen);

	return ret;
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
