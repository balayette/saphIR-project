#include "lifter/disas.hh"
#include "utils/assert.hh"

namespace lifter
{
disas_insn::disas_insn(const cs_insn &insn, csh handle)
    : insn_(insn), handle_(handle)
{
}

std::string disas_insn::as_str() const
{
	return std::string(insn_.mnemonic) + " " + std::string(insn_.op_str);
}

std::string disas_insn::group_name(unsigned int group) const
{
	return cs_group_name(handle_, group);
}

bool disas_insn::ends_bb() const
{
	return cs_insn_group(handle_, &insn_, ARM64_GRP_JUMP)
	       || cs_insn_group(handle_, &insn_, ARM64_GRP_CALL)
	       || cs_insn_group(handle_, &insn_, ARM64_GRP_RET);
}

bool disas_insn::is_ret() const
{
	return cs_insn_group(handle_, &insn_, ARM64_GRP_RET);
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
		ret += insn.as_str() + "\n";
	return ret;
}

disas::disas(const uint8_t *buf, size_t sz)
{
	ASSERT(cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle_) == CS_ERR_OK,
	       "Couldn't init capstone");
	cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);

	insn_count_ = cs_disasm(handle_, buf, sz, 0, 0, &insn_);
	ASSERT(insn_count_ > 0, "Couldn't disas");
}

disas::~disas()
{
	cs_free(insn_, insn_count_);
	cs_close(&handle_);
}

disas_insn disas::operator[](size_t idx) const
{
	ASSERT(idx < insn_count_, "Instruction out of range");
	return disas_insn(insn_[idx], handle_);
}
} // namespace lifter
