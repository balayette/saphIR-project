#pragma once

#include <vector>
#include <optional>
#include <string>
#include <unordered_map>
#include <map>
#include <sys/mman.h>
#include <variant>

#include "utils/ref.hh"
#include "fmt/format.h"

namespace dyn
{
using vaddr_t = std::uintptr_t;

#define MMU_PAGE_SZ (4096)

enum class mmu_status : uint64_t {
	OK = 0,
	INVALID_PARAMS,
	NOT_MAPPED,
	ALREADY_MAPPED,
	WRONG_PROTS,
	OUT_OF_MEM,
};

class mmu_page
{
      public:
	mmu_page() = default;

	mmu_page(vaddr_t start, int prots)
	    : start_(start), end_(start_ + MMU_PAGE_SZ - 1), prots_(prots),
	      data_(new uint8_t[MMU_PAGE_SZ]()), dirty_(false), new_(true)
	{
	}

	bool contains(vaddr_t addr) const;

	size_t size() const { return MMU_PAGE_SZ; }
	vaddr_t start() const { return start_; }
	vaddr_t end() const { return end_; }
	int prots() const { return prots_; }
	void update_prots(int prots) { prots_ = prots; }

	/*
	 * A page is dirty when it has been written to.
	 * On a write, if the page is !dirty_ and !new_, CoW takes place, and
	 * dirty_ is set. A page is new_ when it is allocated. The MMU unsets
	 * new_ in make_base_state(). This makes MMU resets faster by clearly
	 * indicating which pages were allocated after the base state.
	 */
	bool dirty() const { return dirty_; }
	bool is_new() const { return new_; }
	void make_base()
	{
		new_ = false;
		dirty_ = false;
	}

	std::string to_string() const
	{
		return fmt::format("[{:#x} => {:#x} ({:#x}) {} {} {:03b}]",
				   start_, end_, MMU_PAGE_SZ,
				   dirty_ ? 'D' : 'C', new_ ? 'N' : 'O',
				   prots_);
	}

	std::string dump() const
	{
		std::string ret;

		for (size_t i = 0; i < MMU_PAGE_SZ; i++)
			ret += fmt::format("{:x}", data_[i]);

		return ret;
	}

	/*
	 * Potentially triggers CoW
	 */
	mmu_status write(vaddr_t addr, const void *data, size_t sz);
	mmu_status read(void *data, vaddr_t addr, size_t sz);

      private:
	void cow();
	uint64_t page_offt(vaddr_t addr) const { return addr - start_; }
	void *data_offt(vaddr_t addr) { return data_.get() + page_offt(addr); }

	vaddr_t start_;
	vaddr_t end_;

	int prots_;

	std::shared_ptr<uint8_t[]> data_;

	bool dirty_;
	bool new_;
};

/*
 * This mmu is only for access in single threaded programs, it does not contain
 * any locks yet.
 */
class mmu
{
      private:
	using mmu_const_it = std::map<vaddr_t, mmu_page>::const_iterator;
	using mmu_it = std::map<vaddr_t, mmu_page>::iterator;

      public:
	mmu(vaddr_t mmap_base, size_t mem_sz)
	    : mem_sz_(mem_sz), curr_sz_(0), mmap_base_(mmap_base),
	      mmap_curr_(mmap_base)
	{
	}

	std::variant<mmu_status, vaddr_t>
	mmap(vaddr_t addr, size_t length, int prot = PROT_WRITE | PROT_READ,
	     int flags = MAP_ANONYMOUS | MAP_PRIVATE, int fd = -1,
	     off_t offset = 0);
	mmu_status munmap(vaddr_t addr, size_t length);
	mmu_status mprotect(vaddr_t addr, size_t length, int prots);

	/*
	 * Read and write do not check if the entire range is reachable before
	 * starting to read/write, which should be fine.
	 */
	mmu_status write(vaddr_t addr, const void *data, size_t sz);
	mmu_status read(void *data, vaddr_t addr, size_t sz);

	template <typename T> mmu_status write(vaddr_t addr, const T val);
	template <typename T> std::variant<mmu_status, T> read(vaddr_t addr);

	void make_base_state();

	void reset(const mmu &base);

	size_t size() const { return curr_sz_; }
	std::string to_string() const;
	std::string dump() const;

      private:
	mmu_status mmap_fixed(vaddr_t start, size_t length, int prots);

	size_t mem_sz_;
	size_t curr_sz_;

	vaddr_t mmap_base_;
	vaddr_t mmap_curr_;

	std::map<vaddr_t, mmu_page> pages_;
};
} // namespace dyn

#include "dyn/mmu.hxx"
