#pragma once


namespace frontend
{
/* statements */
struct stmt;
struct decs;
struct globaldec;
struct structdec;
struct memberdec;
struct locdec;
struct funprotodec;
struct fundec;
struct sexp;
struct ret;
struct ifstmt;
struct forstmt;

/* expressions */
struct paren;
struct braceinit;
struct bin;
struct unary;
struct ass;
struct cmp;
struct num;
struct ref;
struct deref;
struct addrof;
struct call;
struct str_lit;
struct memberaccess;
struct arrowaccess;
struct subscript;


#define ACCEPT(X)                                                              \
	virtual void accept(visitor &visitor) override                         \
	{                                                                      \
		visitor.visit_##X(*this);                                      \
	}

class visitor
{
      public:
	/* statements */
	virtual void visit_decs(decs &s) = 0;
	virtual void visit_structdec(structdec &s) = 0;
	virtual void visit_memberdec(memberdec &s) = 0;
	virtual void visit_globaldec(globaldec &s) = 0;
	virtual void visit_locdec(locdec &s) = 0;
	virtual void visit_funprotodec(funprotodec &s) = 0;
	virtual void visit_fundec(fundec &s) = 0;
	virtual void visit_sexp(sexp &s) = 0;
	virtual void visit_ret(ret &s) = 0;
	virtual void visit_ifstmt(ifstmt &s) = 0;
	virtual void visit_forstmt(forstmt &s) = 0;
	virtual void visit_ass(ass &s) = 0;

	/* expressions */
	virtual void visit_paren(paren &e) = 0;
	virtual void visit_braceinit(braceinit &e) = 0;
	virtual void visit_bin(bin &e) = 0;
	virtual void visit_unary(unary &e) = 0;
	virtual void visit_cmp(cmp &e) = 0;
	virtual void visit_num(num &e) = 0;
	virtual void visit_ref(ref &e) = 0;
	virtual void visit_deref(deref &e) = 0;
	virtual void visit_addrof(addrof &e) = 0;
	virtual void visit_call(call &e) = 0;
	virtual void visit_str_lit(str_lit &e) = 0;
	virtual void visit_memberaccess(memberaccess &e) = 0;
	virtual void visit_arrowaccess(arrowaccess &e) = 0;
	virtual void visit_subscript(subscript &e) = 0;
};
} // namespace frontend
