#include "ass/instr.hh"

namespace assem::aarch64
{
struct simple_move : public move {
	simple_move(assem::temp dst, assem::temp src);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	virtual bool is_simple_move() const override { return true; }

	virtual bool removable() const override
	{
		return dst() == src() && dst().size_ <= src().size_;
	}

	assem::temp dst() const { return dst_[0]; }
	assem::temp src() const { return src_[0]; }
};

struct load : public oper {
	load(assem::temp dst, assem::temp src, unsigned sz);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	unsigned sz_;
};

struct store : public oper {
	store(assem::temp addr, assem::temp value, unsigned sz);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	unsigned sz_;
};
} // namespace assem::aarch64
