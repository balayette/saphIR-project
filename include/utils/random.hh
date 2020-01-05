#pragma once

namespace utils
{
template <typename T> T rand(T low, T high);
template <typename It> It choose(It beg, It end);
}

#include "utils/random.hxx"
