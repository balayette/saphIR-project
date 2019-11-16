#pragma once

#include <vector>
#include "symbol.hh"
#include "visitor.hh"
#include "types.hh"
#include "exp.hh"

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
	dec(ty type, symbol name) : type_(type), name_(name) {}

	virtual void accept(visitor &visitor) = 0;

	ty type_;
	symbol name_;
};

struct vardec : public dec {
	vardec(ty type, symbol name, exp *rhs) : dec(type, name), rhs_(rhs) {}
	virtual ~vardec() override { delete rhs_; }

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_vardec(*this);
	}

	exp *rhs_;
};

struct argdec : public dec {
	argdec(ty type, symbol name) : dec(type, name) {}

	ACCEPT(argdec)
};

inline std::ostream &operator<<(std::ostream &os, const dec &dec)
{
	return os << ty_to_string(dec.type_) << ' ' << dec.name_;
}

struct fundec : public stmt {
	fundec(ty ret_ty, symbol name, std::vector<argdec *> args,
	       std::vector<stmt *> body)
	    : ret_ty_(ret_ty), name_(name), args_(args), body_(body)
	{
	}

	virtual ~fundec() override
	{
		for (auto *arg : args_)
			delete arg;
		for (auto *s : body_)
			delete s;
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_fundec(*this);
	}

	ty ret_ty_;
	symbol name_;
	std::vector<argdec *> args_;
	std::vector<stmt *> body_;
};

struct decs : public stmt {
	decs() {}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_decs(*this);
	}

	virtual ~decs() override
	{
		for (auto *f : fundecs_)
			delete f;
		for (auto *v : vardecs_)
			delete v;
	}

	std::vector<fundec *> fundecs_;
	std::vector<vardec *> vardecs_;
};


struct sexp : public stmt {
	sexp(exp *e) : e_(e) {}
	virtual ~sexp() override { delete e_; }

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_sexp(*this);
	}

	exp *e_;
};

struct ret : public stmt {
	ret(exp *e) : e_(e) {}
	virtual ~ret() override { delete e_; }

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_ret(*this);
	}

	exp *e_;
};

struct ifstmt : public stmt {
	ifstmt(exp *cond, std::vector<stmt *> ibody, std::vector<stmt *> ebody)
	    : cond_(cond), ibody_(ibody), ebody_(ebody)
	{
	}

	virtual ~ifstmt() override
	{
		delete cond_;
		for (auto *s : ibody_)
			delete s;
		for (auto *s : ebody_)
			delete s;
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_ifstmt(*this);
	}

	exp *cond_;
	std::vector<stmt *> ibody_;
	std::vector<stmt *> ebody_;
};

struct forstmt : public stmt {
	forstmt(stmt *init, exp *cond, exp *action, std::vector<stmt *> body)
	    : init_(init), cond_(cond), action_(action), body_(body)
	{
	}

	virtual ~forstmt() override
	{
		delete cond_;
		delete init_;
		delete action_;

		for (auto *s : body_)
			delete s;
	}

	ACCEPT(forstmt)

	stmt *init_;
	exp *cond_;
	exp *action_;
	std::vector<stmt *> body_;
};
