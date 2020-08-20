#pragma once
#include "emu.hh"

namespace dyn
{
template <typename N> void emu::add_with_carry(N x, N y, int carry)
{
	__uint128_t usum = (__uint128_t)x + (__uint128_t)y + carry;
	__int128_t ssum = (__int128_t)x + (__int128_t)y + carry;

	N result = usum;

	if (result & (1ull << (sizeof(N) * 8 - 1)))
		state_.nzcv |= lifter::N;
	if (result == 0)
		state_.nzcv |= lifter::Z;
	if ((__uint128_t)result != usum)
		state_.nzcv |= lifter::C;
	if ((__int128_t)result != ssum)
		state_.nzcv |= lifter::V;
}
} // namespace dyn
