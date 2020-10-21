#pragma once

#include "dyn/mmu.hh"

namespace dyn
{
template <typename T> T mmu::read(vaddr_t addr)
{
	T res;
	read(reinterpret_cast<uint8_t *>(&res), addr, sizeof(T));

	return res;
}

template <typename T> void mmu::write(vaddr_t addr, const T val)
{
	write(addr, reinterpret_cast<const uint8_t *>(&val), sizeof(T));
}
} // namespace dyn
