#pragma once

#include <vector>
#include "utils/symbol.hh"
#include "frontend/visitors/visitor.hh"
#include "ir/types.hh"
#include "exp.hh"
#include "mach/target.hh"
#include "utils/ref.hh"

namespace frontend
{
struct stmt {
      protected:
	stmt() = default;
	stmt(const stmt &rhs) = default;
	stmt &operator=(const stmt &rhs) = default;

      public:
	virtual ~stmt() = default;
	virtual void accept(visitor &visitor) = 0;
};

struct dec : public stmt {
	dec(utils::ref<types::ty> type, symbol name, bool escapes = false)
	    : type_(type), name_(name), escapes_(escapes)
	{
	}

	virtual void accept(visitor &visitor) = 0;

	utils::ref<types::ty> type_;
	symbol name_;
	utils::ref<mach::access> access_;
	bool escapes_;
};

struct tydec : public dec {
	tydec(symbol name);

	virtual void accept(visitor &visitor) = 0;
};

struct memberdec : public dec {
	memberdec(utils::ref<types::ty> type, symbol name) : dec(type, name) {}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_memberdec(*this);
	}
};

struct structdec : public tydec {
	structdec(symbol name, std::vector<utils::ref<memberdec>> members)
	    : tydec(name), members_(members)
	{
	}

	virtual void accept(visitor &visitor)
	{
		visitor.visit_structdec(*this);
	}

	std::vector<utils::ref<memberdec>> members_;
};

struct vardec : public dec {
	vardec(utils::ref<types::ty> type, symbol name) : dec(type, name) {}
};

struct globaldec : public vardec {
	globaldec(utils::ref<types::ty> type, symbol name, utils::ref<exp> rhs)
	    : vardec(type, name), rhs_(rhs)
	{
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_globaldec(*this);
	}

	utils::ref<exp> rhs_;
};

struct locdec : public vardec {
	locdec(utils::ref<types::ty> type, symbol name, utils::ref<exp> rhs)
	    : vardec(type, name), rhs_(rhs)
	{
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_locdec(*this);
	}

	utils::ref<exp> rhs_;
};

std::ostream &operator<<(std::ostream &os, const vardec &dec);

struct funprotodec : public dec {
	funprotodec(utils::ref<types::ty> ret_ty, symbol name,
		    std::vector<utils::ref<locdec>> args, bool variadic = false)
	    : dec(ret_ty, name, true), args_(args), variadic_(variadic)
	{
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_funprotodec(*this);
	}

	std::vector<utils::ref<locdec>> args_;
	bool variadic_;
};

struct fundec : public funprotodec {
	fundec(utils::ref<types::ty> ret_ty, symbol name,
	       std::vector<utils::ref<locdec>> args,
	       std::vector<utils::ref<stmt>> body)
	    : funprotodec(ret_ty, name, args), body_(body), has_return_(false)
	{
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_fundec(*this);
	}

	std::vector<utils::ref<stmt>> body_;
	utils::ref<mach::frame> frame_;
	bool has_return_;
};

/* This is the toplevel node in the AST */
struct decs : public stmt {
	decs() {}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_decs(*this);
	}

	std::vector<utils::ref<dec>> decs_;
};


struct sexp : public stmt {
	sexp(utils::ref<exp> e) : e_(e) {}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_sexp(*this);
	}

	utils::ref<exp> e_;
};

struct ret : public stmt {
	ret(utils::ref<exp> e) : e_(e), fdec_(nullptr) {}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_ret(*this);
	}

	utils::ref<exp> e_;

	fundec *fdec_;
};

struct ifstmt : public stmt {
	ifstmt(utils::ref<exp> cond, std::vector<utils::ref<stmt>> ibody,
	       std::vector<utils::ref<stmt>> ebody)
	    : cond_(cond), ibody_(ibody), ebody_(ebody)
	{
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_ifstmt(*this);
	}

	utils::ref<exp> cond_;
	std::vector<utils::ref<stmt>> ibody_;
	std::vector<utils::ref<stmt>> ebody_;
};

struct forstmt : public stmt {
	forstmt(utils::ref<stmt> init, utils::ref<exp> cond,
		utils::ref<stmt> action, std::vector<utils::ref<stmt>> body)
	    : init_(init), cond_(cond), action_(action), body_(body)
	{
	}

	ACCEPT(forstmt)

	utils::ref<stmt> init_;
	utils::ref<exp> cond_;
	utils::ref<stmt> action_;
	std::vector<utils::ref<stmt>> body_;
};

struct ass : public stmt {
	ass(utils::ref<exp> lhs, utils::ref<exp> rhs)
	    : lhs_(lhs), rhs_(rhs), dec_(nullptr)
	{
	}

	ACCEPT(ass)

	utils::ref<exp> lhs_;
	utils::ref<exp> rhs_;

	utils::ref<dec> dec_;
};

struct asm_reg_map {
	asm_reg_map() = default;
	asm_reg_map(const std::string &regstr, utils::ref<exp> e)
	    : regstr_(regstr), e_(e)
	{
	}

	std::string regstr_;
	utils::ref<exp> e_;
};

struct inline_asm : public stmt {
	inline_asm(const std::vector<asm_reg_map> &reg_in,
		   const std::vector<asm_reg_map> &reg_out,
		   const std::vector<std::string> &reg_clob,
		   const std::vector<std::string> &lines)
	    : reg_in_(reg_in), reg_out_(reg_out), reg_clob_(reg_clob),
	      lines_(lines)
	{
	}

	ACCEPT(inline_asm)

	std::vector<asm_reg_map> reg_in_;
	std::vector<asm_reg_map> reg_out_;
	std::vector<std::string> reg_clob_;
	std::vector<std::string> lines_;
};

} // namespace frontend
