#pragma once

#include "dyn/mmu.hh"

namespace dyn
{
template <typename T> std::variant<mmu_status, T> mmu::read(vaddr_t addr)
{
	T res;
	auto ret = read(&res, addr, sizeof(T));
	if (ret == mmu_status::OK)
		return res;
	return ret;
}

template <typename T> mmu_status mmu::write(vaddr_t addr, const T val)
{
	return write(addr, &val, sizeof(T));
}
} // namespace dyn
