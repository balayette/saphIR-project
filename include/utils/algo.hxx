#pragma once
#include "utils/algo.hh"
#include <algorithm>

namespace utils
{
template <typename Container, typename Pred>
bool all_of(const Container &c, Pred pred)
{
	return std::all_of(c.begin(), c.end(), pred);
}
} // namespace utils
