#include "lifter/disas.hh"
#include "utils/assert.hh"
#include <iostream>
#include "fmt/format.h"

namespace lifter
{
disas_insn::disas_insn(std::shared_ptr<cs_insn> insn, csh handle)
    : insn_(insn), handle_(handle)
{
}

size_t disas_insn::address() const { return insn_->address; }

std::string disas_insn::as_str() const
{
	return fmt::format("{:#8x}\t{}\t{}", address(), insn_->mnemonic,
			   insn_->op_str);
}

std::string disas_insn::group_name(unsigned int group) const
{
	return cs_group_name(handle_, group);
}

bool disas_insn::ends_bb() const
{
	return cs_insn_group(handle_, insn_.get(), ARM64_GRP_JUMP)
	       || cs_insn_group(handle_, insn_.get(), ARM64_GRP_CALL)
	       || cs_insn_group(handle_, insn_.get(), ARM64_GRP_RET);
}

bool disas_insn::is_ret() const
{
	return cs_insn_group(handle_, insn_.get(), ARM64_GRP_RET);
}

void disas_bb::append(const disas_insn &insn)
{
	ASSERT(!complete_, "Basic block already completed");
	complete_ = insn.ends_bb();

	if (complete_)
		end_insn_ = insn;
	else
		insns_.push_back(insn);
}

std::string disas_bb::dump() const
{
	std::string ret;
	for (const auto &insn : insns_)
		ret += insn.as_str() + '\n';
	ret += end_insn_.as_str() + '\n';
	return ret;
}

disas::disas()
{
	ASSERT(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle_) == CS_ERR_OK,
	       "Couldn't init capstone");
	cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
}

disas_bb disas::next(const uint8_t *buf, size_t sz, size_t addr)
{
	disas_bb ret(addr);

	for (size_t i = 0; sz > 0; i += 4, sz -= 4) {
		cs_insn *insn;
		ASSERT(cs_disasm(handle_, buf + i, sz, addr + i, 1, &insn),
		       "Couldn't disas instruction");

		ret.append(disas_insn(
			std::shared_ptr<cs_insn>(
				insn, [](cs_insn *insn) { cs_free(insn, 1); }),
			handle_));

		insn = nullptr;
		if (ret.complete())
			return ret;
	}

	UNREACHABLE("Unfinished basic block");
}

disas::~disas() { cs_close(&handle_); }
} // namespace lifter
