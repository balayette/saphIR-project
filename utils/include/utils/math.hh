#pragma once

namespace utils::math
{
/*
 * % is the remainder and not the modulo
 */
static inline int64_t mod(int64_t a, int64_t b)
{
	int r = a % b;
	return r < 0 ? r + b : r;
}
} // namespace utils::math
