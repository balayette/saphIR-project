#include "lifter/lifter.hh"
#include "lifter/disas.hh"
#include "utils/fs.hh"
#include "elf/elf.hh"
#include "keystone/keystone.h"
#include <unordered_map>

namespace dyn
{
struct register_bank {
	uint64_t regs[32];
};

struct chunk {
	void *map;
	size_t size;
};

class emu
{
      public:
	emu(utils::mapped_file &file);
	~emu();
	void run();
	register_bank &regs() { return regs_; }
        std::string state_dump() const;

      private:
	using bb_fn = void (*)(register_bank *);

	const chunk &find_or_compile(size_t pc);
	chunk compile(size_t pc);
	chunk assemble(mach::target &target, std::vector<assem::rinstr> &instrs,
		       utils::label body_lbl);

	utils::mapped_file &file_;
	elf::elf bin_;
	ks_engine *ks_;

	lifter::lifter lifter_;
	lifter::disas disas_;

	register_bank regs_;
	size_t pc_;

	std::unordered_map<size_t, chunk> bb_cache_;
};
} // namespace dyn
