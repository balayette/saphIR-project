#include "dyn/mmu.hh"
#include "utils/assert.hh"
#include <fstream>

namespace dyn
{
mmu::mmu_it mmu::overlaps(vaddr_t start, size_t sz)
{
	vaddr_t end = start + sz - 1;

	for (auto it = ranges_.begin(); it != ranges_.end(); it++) {
		if (start <= it->end() && it->start() <= end)
			return it;
	}

	return ranges_.end();
}

bool mmu::map_addr(vaddr_t start, size_t sz, int prots)
{
	fmt::print("Mappping {:#x} {:#x} {:#x}\n", start, sz,
		   mem_sz_ - curr_sz_);
	ASSERT(curr_sz_ + sz <= mem_sz_, "out of memory, would need {:#x}",
	       curr_sz_ + sz);

	auto overlap = overlaps(start, sz);
	ASSERT(overlap == ranges_.end(), "Overlapping allocation");

	mmu_range r(start, sz, prots);

	ranges_.insert(std::upper_bound(ranges_.begin(), ranges_.end(), r,
					[](const auto &a, const auto &b) {
						return a.start() < b.start();
					}),
		       r);

	curr_sz_ += sz;

	return true;
}

void mmu::read(uint8_t *dest, vaddr_t addr, size_t sz)
{
	while (sz) {
		auto range = overlaps(addr, sz);

		ASSERT(range != ranges_.end(),
		       "Read of size {} unmapped at address {:#x}", sz, addr);
		ASSERT(range->start() <= addr,
		       "Read of size {} at address {:#x} underflows", sz, addr);

		size_t skip = addr - range->start();
		size_t to_copy = std::min(sz, range->size() - skip);

		std::memcpy(dest, range->data() + skip, to_copy);

		addr = range->end() + 1;
		sz -= to_copy;
		dest += to_copy;
	}
}

void mmu::write(vaddr_t addr, const uint8_t *src, size_t sz)
{
	while (sz) {
		auto range = overlaps(addr, sz);

		ASSERT(range != ranges_.end(),
		       "Write of size {} unmapped at address {:#x}", sz, addr);
		ASSERT(range->start() <= addr,
		       "Write of size {} at address {:#x} underflows", sz,
		       addr);

		/*
		 * If we are writing to a range that was not modified before,
		 * CoW
		 */
		if (!range->dirty())
			*range = range->cow();

		size_t skip = addr - range->start();
		size_t to_copy = std::min(sz, range->size() - skip);

		std::memcpy(range->data() + skip, src, to_copy);

		addr = range->end() + 1;
		sz -= to_copy;
		src += to_copy;
	}
}

void mmu::reset(const mmu &base)
{
	curr_sz_ = base.curr_sz_;
	ranges_.clear();

	for (const auto &r : base.ranges_) {
		mmu_range nrange(r.start(), r.size(), r.prots());
		std::memcpy(nrange.data(), r.data(), r.size());
		ranges_.push_back(nrange);
	}
}

void mmu::dump_memory(const std::string &fname) const
{
	std::ofstream file(fname);

	for (const auto &r : ranges_) {
		auto *data = r.data();
		size_t sz = r.size();

		for (size_t i = 0; i < sz; i++)
			file << data[i];
	}
}
} // namespace dyn
