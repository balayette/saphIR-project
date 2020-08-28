#include "lifter/disas.hh"
#include "utils/assert.hh"
#include <iostream>
#include "fmt/format.h"

namespace lifter
{
disas_insn::disas_insn(std::shared_ptr<cs_insn> insn, csh handle)
    : insn_(insn), handle_(handle)
{
	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;

	if (cs_regs_access(handle, insn.get(), regs_read, &read_count,
			   regs_write, &write_count)
	    == CS_ERR_OK) {
		for (size_t i = 0; i < read_count; i++)
			regs_ += regs_read[i];
		for (size_t i = 0; i < write_count; i++)
			regs_ += regs_write[i];
	}

	regs_ -= ARM64_REG_NZCV;
	regs_ -= ARM64_REG_XZR;
	regs_ -= ARM64_REG_WZR;

        /*
         * 'ret' really is 'ret x30', but capstone does not list x30 in the
         * accessed registers.
         */
	if (is_ret() && mach_detail()->op_count == 0)
		regs_ += ARM64_REG_X30;
}

size_t disas_insn::address() const { return insn_->address; }

std::string disas_insn::as_str() const
{
	return fmt::format("{:#8x}\t{}\t{}", address(), insn_->mnemonic,
			   insn_->op_str);
}

std::string disas_insn::insn_name() const
{
	return cs_insn_name(handle_, insn_->id);
}

std::string disas_insn::group_name(unsigned int group) const
{
	return cs_group_name(handle_, group);
}

bool disas_insn::ends_bb() const
{
	auto *mach_det = mach_detail();

	return cs_insn_group(handle_, insn_.get(), ARM64_GRP_JUMP)
	       || cs_insn_group(handle_, insn_.get(), ARM64_GRP_CALL)
	       || cs_insn_group(handle_, insn_.get(), ARM64_GRP_RET)
	       || cs_insn_group(handle_, insn_.get(), ARM64_GRP_INT)
	       || mach_det->update_flags;
}

bool disas_insn::is_ret() const
{
	return cs_insn_group(handle_, insn_.get(), ARM64_GRP_RET);
}

void disas_bb::append(const disas_insn &insn)
{
	ASSERT(!complete_, "Basic block already completed");
	complete_ = insn.ends_bb();
	insns_.push_back(insn);

	regs_ += insn.regs();
}

std::string disas_bb::dump() const
{
	std::string ret;
	for (const auto &insn : insns_)
		ret += insn.as_str() + '\n';
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
