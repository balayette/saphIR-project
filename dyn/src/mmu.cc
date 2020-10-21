#include "dyn/mmu.hh"
#include "utils/assert.hh"
#include "utils/misc.hh"
#include <fstream>

namespace dyn
{
mmu::mmu_it mmu::overlaps(vaddr_t start, size_t sz)
{
	ASSERT(start % MMU_PAGE_SZ == 0, "Address must be aligned");

	for (vaddr_t addr = start; addr < start + sz; addr += MMU_PAGE_SZ) {
		auto it = pages_.find(addr);
		if (it != pages_.end())
			return it;
	}

	return pages_.end();
}

bool mmu::map_addr(vaddr_t start, size_t sz, int prots)
{
	ASSERT(curr_sz_ + sz <= mem_sz_, "out of memory, would need {:#x}",
	       curr_sz_ + sz);

	start = ROUND_DOWN(start, MMU_PAGE_SZ);
	auto overlap = overlaps(start, sz);
	ASSERT(overlap == pages_.end(), "Overlapping allocation");

	for (vaddr_t address = start; address < start + sz;
	     address += MMU_PAGE_SZ) {
		pages_[address] = mmu_page(address, prots);
	}

	curr_sz_ += sz;

	return true;
}

void mmu::read(uint8_t *dest, vaddr_t addr, size_t sz)
{
	while (sz) {
		auto it = overlaps(ROUND_DOWN(addr, MMU_PAGE_SZ), sz);

		ASSERT(it != pages_.end(),
		       "Read of size {} unmapped at address {:#x}", sz, addr);

		auto &range = it->second;
		ASSERT(range.start() <= addr,
		       "Read of size {} at address {:#x} underflows", sz, addr);

		size_t skip = addr - range.start();
		size_t to_copy = std::min(sz, range.size() - skip);

		std::memcpy(dest, range.data() + skip, to_copy);

		addr = range.end() + 1;
		sz -= to_copy;
		dest += to_copy;
	}
}

void mmu::write(vaddr_t addr, const uint8_t *src, size_t sz)
{
	while (sz) {
		auto it = overlaps(ROUND_DOWN(addr, MMU_PAGE_SZ), sz);

		ASSERT(it != pages_.end(),
		       "Write of size {} unmapped at address {:#x}", sz, addr);

		auto &range = it->second;
		ASSERT(range.start() <= addr,
		       "Write of size {} at address {:#x} underflows", sz,
		       addr);

		/*
		 * If we are writing to a range that was not modified before,
		 * CoW
		 */
		if (!range.dirty())
			range = range.cow();

		size_t skip = addr - range.start();
		size_t to_copy = std::min(sz, range.size() - skip);

		std::memcpy(range.data() + skip, src, to_copy);

		addr = range.end() + 1;
		sz -= to_copy;
		src += to_copy;
	}
}

void mmu::reset(const mmu &base)
{
	curr_sz_ = base.curr_sz_;

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
		page.set_dirty(false);
		std::memcpy(page.data(), base_page->second.data(), page.size());
	}
}

void mmu::dump_memory(const std::string &fname) const
{
	std::ofstream file(fname);

	for (const auto &[_, r] : pages_) {
		auto *data = r.data();
		size_t sz = r.size();

		for (size_t i = 0; i < sz; i++)
			file << data[i];
	}
}
} // namespace dyn
