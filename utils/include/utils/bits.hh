#pragma once

namespace utils
{
template <typename T>
static inline T extract_bits(const T bits, const uint32_t msb,
			     const uint32_t lsb)
{
	return (bits >> lsb) & ((1ull << (msb - lsb + 1)) - 1);
}

template <typename T>
static inline T extract_bit(const T bits, const uint32_t bit)
{
	return (bits >> bit) & 1ull;
}

static inline uint64_t mask_range(uint64_t lo, uint64_t hi)
{
	uint64_t count = hi - lo + 1;
	uint64_t mask;
	if (count == 64)
		mask = ~0ull;
	else
		mask = (1ull << count) - 1;

	return mask << lo;
}
} // namespace utils
