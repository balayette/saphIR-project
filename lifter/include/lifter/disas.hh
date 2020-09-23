#pragma once

#include "capstone/capstone.h"
#include "utils/uset.hh"
#include <string>
#include <memory>
#include <vector>

namespace lifter
{
class disas_insn
{
      public:
	disas_insn() = default;
	disas_insn(std::shared_ptr<cs_insn> insn, csh handle);

	size_t address() const;
	std::string as_str() const;
	std::string insn_name() const;

	const cs_insn &insn() const { return *insn_; }
	const cs_detail *detail() const { return insn_->detail; }
	const cs_arm64 *mach_detail() const { return &insn_->detail->arm64; }

	enum arm64_insn id() const
	{
		return static_cast<arm64_insn>(insn_->id);
	}

	bool ends_bb() const;
	bool is_ret() const;

	std::string group_name(unsigned int group) const;

	const utils::uset<uint16_t> regs() const { return regs_; }

      private:
	std::shared_ptr<cs_insn> insn_;
	csh handle_;

	utils::uset<uint16_t> regs_;
};

class disas_bb
{
      public:
	disas_bb(size_t addr) : addr_(addr), complete_(false) {}
	void append(const disas_insn &insn);
	bool complete() const { return complete_; }
	const std::vector<disas_insn> insns() const { return insns_; }
	size_t address() const { return addr_; }

	std::string dump() const;
	size_t size() const { return insns_.size(); }

	const utils::uset<uint16_t> regs() const { return regs_; }

      private:
	size_t addr_;
	std::vector<disas_insn> insns_;
	bool complete_;

	utils::uset<uint16_t> regs_;
};

class disas
{
      public:
	/*
	 * singlestep mode means that each basic block will contain a single
	 * instruction, even if the instruction does not actually end a normal
	 * basic block. Thus disas_bb::complete() will be false.
	 */
	disas(bool singlestep = false);
	~disas();

	disas_bb next(const uint8_t *buf, size_t sz, size_t addr);

      private:
	csh handle_;
	bool singlestep_;
};
} // namespace lifter
