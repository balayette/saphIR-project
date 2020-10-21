#pragma once

#include <vector>
#include <optional>
#include <string>

#include "utils/ref.hh"
#include "fmt/format.h"

namespace dyn
{
using vaddr_t = std::uintptr_t;

class mmu_range
{
      public:
	mmu_range(vaddr_t start, size_t sz, int prots)
	    : start_(start), sz_(sz), end_(start_ + sz_ - 1), prots_(prots),
	      data_(new uint8_t[sz_]), dirty_(false)
	{
	}

	size_t size() const { return sz_; }
	vaddr_t start() const { return start_; }
	vaddr_t end() const { return end_; }
	int prots() const { return prots_; }
	bool dirty() const { return dirty_; }
	void set_dirty(bool v = true) { dirty_ = v; }

	uint8_t *data() const { return data_.get(); }

	std::string to_string() const
	{
		return fmt::format("[{:#x} => {:#x} ({:#x}) {}]", start_, end_,
				   sz_, dirty_ ? 'D' : 'C');
	}

	mmu_range cow() const
	{
		fmt::print("CoW of range {:#x} {:#x}\n", start_, end_);
		mmu_range ret(start_, sz_, prots_);
		ret.dirty_ = true;
		std::memcpy(ret.data(), &data_, sz_);

		return ret;
	}

      private:
	vaddr_t start_;
	size_t sz_;
	vaddr_t end_;

	int prots_;

	utils::ref<uint8_t> data_;

	bool dirty_;
};

class mmu
{
      private:
	using mmu_const_it = std::vector<mmu_range>::const_iterator;
	using mmu_it = std::vector<mmu_range>::iterator;

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

	std::vector<mmu_range> ranges_;
};
} // namespace dyn

#include "dyn/mmu.hxx"
