#pragma once

#include <vector>
#include "utils/symbol.hh"
#include "frontend/visitors/visitor.hh"
#include "types.hh"
#include "exp.hh"
#include "mach/frame.hh"
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
	dec(types::ty type, symbol name)
	    : type_(type), name_(name), escapes_(false)
	{
	}

	virtual void accept(visitor &visitor) = 0;

	types::ty type_;
	symbol name_;
	bool escapes_;
	utils::ref<frame::access> access_;
};

struct vardec : public dec {
	vardec(types::ty type, symbol name, exp *rhs)
	    : dec(type, name), rhs_(rhs)
	{
	}
	virtual ~vardec() override { delete rhs_; }

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_vardec(*this);
	}

	exp *rhs_;
};

struct argdec : public dec {
	argdec(types::ty type, symbol name) : dec(type, name) {}

	ACCEPT(argdec)
};

std::ostream &operator<<(std::ostream &os, const dec &dec);

struct fundec : public stmt {
	fundec(types::ty ret_ty, symbol name, std::vector<argdec *> args,
	       std::vector<stmt *> body)
	    : ret_ty_(ret_ty), name_(name), args_(args), body_(body),
	      has_return_(false)
	{
	}

	virtual ~fundec() override
	{
		for (auto *arg : args_)
			delete arg;
		for (auto *s : body_)
			delete s;
		delete frame_;
	}

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_fundec(*this);
	}

	types::ty ret_ty_;
	symbol name_;
	std::vector<argdec *> args_;
	std::vector<stmt *> body_;
	frame::frame *frame_;
	bool has_return_;
};

/* This is the toplevel node in the AST */
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
	ret(exp *e) : e_(e), fdec_(nullptr) {}
	virtual ~ret() override { delete e_; }

	virtual void accept(visitor &visitor) override
	{
		visitor.visit_ret(*this);
	}

	exp *e_;

	fundec *fdec_;
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
	forstmt(stmt *init, exp *cond, stmt *action, std::vector<stmt *> body)
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
	stmt *action_;
	std::vector<stmt *> body_;
};

struct ass : public stmt {
	ass(exp *lhs, exp *rhs) : lhs_(lhs), rhs_(rhs), dec_(nullptr) {}

	virtual ~ass() override
	{
		delete lhs_;
		delete rhs_;
	}

	ACCEPT(ass)

	exp *lhs_;
	exp *rhs_;

	dec *dec_;
};

} // namespace frontend
