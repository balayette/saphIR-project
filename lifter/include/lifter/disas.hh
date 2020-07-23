#pragma once

#include "capstone/capstone.h"
#include <string>
#include <vector>

namespace lifter
{
class disas_insn
{
      public:
	disas_insn() = default;
	disas_insn(const cs_insn &insn, csh handle);

	std::string as_str() const;

	const cs_insn &insn() const { return insn_; }
	const cs_detail *detail() const { return insn_.detail; }
	const cs_arm64 *mach_detail() const { return &insn_.detail->arm64; }

	enum arm64_insn id() const { return static_cast<arm64_insn>(insn_.id); }

	bool ends_bb() const;
	bool is_ret() const;

	std::string group_name(unsigned int group) const;

      private:
	cs_insn insn_;
	csh handle_;
};

class disas_bb
{
      public:
	disas_bb() : complete_(false) {}
	void append(const disas_insn &insn);
	bool complete() const { return complete_; }
	const std::vector<disas_insn> insns() const { return insns_; }

	std::string dump() const;

      private:
	std::vector<disas_insn> insns_;
	disas_insn end_insn_;
	bool complete_;
};

class disas
{
      public:
	disas(const uint8_t *buf, size_t sz);
	~disas();

	disas_insn operator[](size_t idx) const;
	size_t insn_count() const { return insn_count_; }

      private:
	csh handle_;
	cs_insn *insn_;
	size_t insn_count_;
};
} // namespace lifter
