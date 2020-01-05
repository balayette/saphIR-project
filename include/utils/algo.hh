#pragma once

namespace utils
{
template <typename Container, typename Pred> bool all_of(const Container &c, Pred pred);
}

#include "utils/algo.hxx"
