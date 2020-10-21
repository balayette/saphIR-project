#pragma once

#include <vector>
#include <optional>
#include <string>

#include "utils/ref.hh"
#include "fmt/format.h"

namespace dyn
{
using vaddr_t = std::uintptr_t;

#define MMU_PAGE_SZ (4096)

class mmu_page
{
      public:
	mmu_page(vaddr_t start, int prots)
	    : start_(start), end_(start_ + MMU_PAGE_SZ - 1), prots_(prots),
	      data_(new uint8_t[MMU_PAGE_SZ]), dirty_(false)
	{
	}

	size_t size() const { return MMU_PAGE_SZ; }
	vaddr_t start() const { return start_; }
	vaddr_t end() const { return end_; }
	int prots() const { return prots_; }
	bool dirty() const { return dirty_; }
	void set_dirty(bool v = true) { dirty_ = v; }

	uint8_t *data() const { return data_.get(); }

	std::string to_string() const
	{
		return fmt::format("[{:#x} => {:#x} ({:#x}) {}]", start_, end_,
				   MMU_PAGE_SZ, dirty_ ? 'D' : 'C');
	}

	mmu_page cow() const
	{
		mmu_page ret(start_, prots_);
		ret.dirty_ = true;
		std::memcpy(ret.data(), &data_, MMU_PAGE_SZ);

		return ret;
	}

      private:
	vaddr_t start_;
	vaddr_t end_;

	int prots_;

	utils::ref<uint8_t> data_;

	bool dirty_;
};

class mmu
{
      private:
	using mmu_const_it = std::vector<mmu_page>::const_iterator;
	using mmu_it = std::vector<mmu_page>::iterator;

      public:
	mmu(size_t mem_sz) : mem_sz_(mem_sz), curr_sz_(0) {}

	bool map_addr(vaddr_t start, size_t sz, int prots);

	void read(uint8_t *dest, vaddr_t addr, size_t sz);
	template <typename T> T read(vaddr_t addr);

	void write(vaddr_t addr, const uint8_t *src, size_t sz);
	template <typename T> void write(vaddr_t addr, const T val);

	void reset(const mmu &base);

	void make_clean_state()
	{
		for (auto &r : ranges_)
			r.set_dirty(false);
	}

	void dump_memory(const std::string &fname) const;

	std::string to_string() const
	{
		auto ret = fmt::format("MMU State: {}%, ({:#x}/{:#x})\n",
				       (double)curr_sz_ / mem_sz_ * 100,
				       curr_sz_, mem_sz_);

		for (const auto &r : ranges_)
			ret += r.to_string() + '\n';

		return ret;
	}

      private:
	mmu_it overlaps(vaddr_t start, size_t sz);

	size_t mem_sz_;
	size_t curr_sz_;

	std::vector<mmu_page> ranges_;
};
} // namespace dyn

#include "dyn/mmu.hxx"
