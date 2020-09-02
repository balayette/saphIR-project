#include "ass/instr.hh"

namespace assem::amd64
{
class addressing
{
      public:
	addressing(assem::temp base);
	addressing(assem::temp base, int64_t disp);
	addressing(std::optional<assem::temp> base, assem::temp index,
		   int64_t scale = 1, int64_t disp = 0);

	const std::optional<assem::temp> &base() const { return base_; }
	const std::optional<assem::temp> &index() const { return index_; }
	std::optional<assem::temp> &base() { return base_; }
	std::optional<assem::temp> &index() { return index_; }

	int64_t disp() const { return disp_; }
	int64_t scale() const { return scale_; }

	/*
	 * Returns the addressing as a assembly string, with register
	 * placeholder indices starting from temp_index.
	 * Updates temp_index to the next available placeholder index
	 */
	std::string to_string(size_t &temp_index) const;
	std::string to_string() const;

	std::vector<assem::temp> regs() const;
	size_t reg_count() const;

      private:
	std::optional<assem::temp> base_;
	int64_t disp_;
	std::optional<assem::temp> index_;
	int64_t scale_;
};

struct sized_oper : public oper {
	sized_oper(const std::string &oper_str, const std::string &op,
		   std::vector<assem::temp> dst, std::vector<assem::temp> src,
		   unsigned sz = 8);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	std::string oper_str_;
	std::string op_;
	unsigned sz_;
};

struct lea : public oper {
	lea(assem::temp dst, std::pair<std::string, assem::temp> src);
	lea(assem::temp dst, std::string src);

	std::string repr() const override;
	std::string lhs_;
};

// a simple move is a reg2reg move
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

/*
 * a complex move is a reg2mem, mem2reg, imm2reg, imm2mem move
 * mem accesses go through registers with known sizes (assem::temps in the src
 * and dst vectors), but we also need the size of the data accessed or written
 * by the mem access.
 */
struct complex_move : public move {
	complex_move(const std::string &dst_str, const std::string &src_str,
		     std::vector<assem::temp> dst, std::vector<assem::temp> src,
		     unsigned dst_sz, unsigned src_sz, types::signedness sign);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	unsigned dst_sz_;
	unsigned src_sz_;

	types::signedness sign_;
};

/*
 * A load is a mem2reg move such as mov 0x10(%rax), %rbx
 */
struct load : public move {
	load(assem::temp dst, addressing addressing, size_t sz);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	assem::temp dest_;
	addressing addressing_;
	size_t sz_;
};

/*
 * A store is a reg2mem such as mov %rbx, 0x10(%rax)
 */
struct store : public move {
	store(addressing addressing, assem::temp src, size_t sz);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	addressing addressing_;
	size_t sz_;
};

/*
 * A store_constant is a imm2mem such as movq $0, 0x10(%rax)
 */
struct store_constant : public move {
	store_constant(addressing addressing, const std::string &constant,
		       size_t sz);

	virtual std::string
	to_string(std::function<std::string(utils::temp, unsigned)> f)
		const override;

	addressing addressing_;
	std::string constant_;
	size_t sz_;
};
} // namespace assem::amd64
