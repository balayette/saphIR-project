#include "dyn/mmu.hh"
#include "utils/assert.hh"
#include "utils/misc.hh"
#include <fstream>

namespace dyn
{
bool mmu_page::contains(vaddr_t addr) const
{
	return addr >= start_ && addr <= end_;
}

mmu_status mmu_page::write(vaddr_t addr, const void *data, size_t sz)
{
	ASSERT(contains(addr), "Addr not in this page");
	ASSERT(addr + sz - 1 <= end_, "Size too large");

	if (!(prots_ & PROT_WRITE))
		return mmu_status::WRONG_PROTS;

	if (!dirty_ && !new_)
		cow();

	std::memcpy(data_offt(addr), data, sz);
	return mmu_status::OK;
}

mmu_status mmu_page::read(void *data, vaddr_t addr, size_t sz)
{
	ASSERT(contains(addr), "Addr not in page");
	ASSERT(addr + sz - 1 <= end_, "Size ({}) too large for address {:#x}",
	       sz, addr);

	if (!(prots_ & PROT_READ))
		return mmu_status::WRONG_PROTS;

	std::memcpy(data, data_offt(addr), sz);
	return mmu_status::OK;
}

void mmu_page::cow()
{
	dirty_ = true;

	auto *new_data = new uint8_t[MMU_PAGE_SZ]();
	std::memcpy(new_data, data_.get(), MMU_PAGE_SZ);

	data_.reset(new_data);
}

mmu_status mmu::mmap_fixed(vaddr_t addr, size_t length, int prot)
{
	for (vaddr_t sz = 0; sz < length; sz += MMU_PAGE_SZ) {
		vaddr_t start = addr + sz;
		if (pages_.find(start) != pages_.end())
			return mmu_status::ALREADY_MAPPED;
	}

	for (vaddr_t sz = 0; sz < length; sz += MMU_PAGE_SZ) {
		vaddr_t start = addr + sz;
		pages_[start] = mmu_page(start, prot);
	}

	return mmu_status::OK;
}

std::variant<mmu_status, vaddr_t> mmu::mmap(vaddr_t addr, size_t length,
					    int prot, int flags, int fd, off_t)
{
	if (addr % MMU_PAGE_SZ != 0)
		return mmu_status::INVALID_PARAMS;

	ASSERT((flags & (MAP_ANONYMOUS | MAP_PRIVATE))
		       == (MAP_ANONYMOUS | MAP_PRIVATE),
	       "mmap flags at least MAP_ANONYMOUS | MAP_PRIVATE");
	ASSERT(fd == -1, "File mapping not supported");

	length = ROUND_UP(length, MMU_PAGE_SZ);
	if (curr_sz_ + length >= mem_sz_)
		return mmu_status::OUT_OF_MEM;

	/*
	 * XXX: If the user has MAP_FIXED an address higher that conflicts with
	 * [map_curr_, map_curr_ + length] the allocation will fail
	 */
	if (!(flags & MAP_FIXED))
		addr = mmap_curr_;

	auto status = mmap_fixed(addr, length, prot);
	if (status != mmu_status::OK)
		return status;

	if (!(flags & MAP_FIXED))
		mmap_curr_ += length;

	curr_sz_ += length;
	return addr;
}

mmu_status mmu::munmap(vaddr_t addr, size_t length)
{
	auto aligned = ROUND_DOWN(addr, MMU_PAGE_SZ);
	length = ROUND_UP(length, MMU_PAGE_SZ);
	if (aligned != addr)
		return mmu_status::NOT_MAPPED;

	for (; length; length -= MMU_PAGE_SZ, aligned += MMU_PAGE_SZ) {
		if (pages_.erase(aligned))
			curr_sz_ -= MMU_PAGE_SZ;
	}

	return mmu_status::OK;
}

mmu_status mmu::mprotect(vaddr_t addr, size_t length, int prots)
{
	auto aligned = ROUND_DOWN(addr, MMU_PAGE_SZ);
	length = ROUND_UP(length, MMU_PAGE_SZ);
	if (aligned != addr)
		return mmu_status::NOT_MAPPED;

	for (; length; length -= MMU_PAGE_SZ, aligned += MMU_PAGE_SZ) {
		auto it = pages_.find(aligned);
		if (it != pages_.end())
			it->second.update_prots(prots);
	}

	return mmu_status::OK;
}

mmu_status mmu::write(vaddr_t addr, const void *data, size_t sz)
{
	while (sz) {
		auto aligned_addr = ROUND_DOWN(addr, MMU_PAGE_SZ);
		size_t max_sz = MMU_PAGE_SZ - (addr - aligned_addr);
		size_t w_sz = std::min(sz, max_sz);

		auto it = pages_.find(aligned_addr);
		if (it == pages_.end())
			return mmu_status::NOT_MAPPED;

		auto ret = it->second.write(addr, data, w_sz);
		if (ret != mmu_status::OK)
			return ret;

		sz -= w_sz;
		data = static_cast<const char *>(data) + w_sz;
		addr = aligned_addr + MMU_PAGE_SZ;
	}

	return mmu_status::OK;
}

mmu_status mmu::read(void *data, vaddr_t addr, size_t sz)
{
	while (sz) {
		auto aligned_addr = ROUND_DOWN(addr, MMU_PAGE_SZ);
		size_t max_sz = MMU_PAGE_SZ - (addr - aligned_addr);
		size_t r_sz = std::min(sz, max_sz);

		auto it = pages_.find(aligned_addr);
		if (it == pages_.end())
			return mmu_status::NOT_MAPPED;

		auto ret = it->second.read(data, addr, r_sz);
		if (ret != mmu_status::OK)
			return ret;

		sz -= r_sz;
		data = static_cast<char *>(data) + r_sz;
		addr = aligned_addr + MMU_PAGE_SZ;
	}

	return mmu_status::OK;
}

void mmu::make_base_state()
{
	for (auto &[_, r] : pages_)
		r.make_base();
}

void mmu::reset(const mmu &base)
{
	curr_sz_ = base.curr_sz_;
	mmap_curr_ = base.mmap_curr_;

	for (auto it = pages_.begin(); it != pages_.end();) {
		if (it->second.is_new())
			it = pages_.erase(it);
		else
			++it;
	}

	for (auto &[addr, page] : pages_) {
		if (!page.dirty())
			continue;

		const auto &base_page = base.pages_.find(addr);
		page = base_page->second;
	}

	// Remap unmapped pages, and reset prots
	for (auto &[addr, page] : base.pages_) {
		auto it = pages_.find(addr);

		if (it != pages_.end())
			pages_[addr].update_prots(page.prots());
		else
			pages_[addr] = page;
	}
}

std::string mmu::to_string() const
{
	std::string ret = fmt::format("{} / {} ({}%)\n", curr_sz_, mem_sz_,
				      (double)curr_sz_ / mem_sz_ * 100);

	for (const auto &[_, r] : pages_)
		ret += r.to_string() + '\n';

	return ret;
}

std::string mmu::dump() const
{
	std::string ret;

	for (const auto &[addr, r] : pages_) {
		ret += fmt::format("{:#x}:\n", addr);
		ret += r.dump();
		ret += "\n";
	}

	return ret;
}
} // namespace dyn
