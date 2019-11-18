#pragma once

/* statements */
struct stmt;
struct decs;
struct vardec;
struct argdec;
struct fundec;
struct sexp;
struct ret;
struct ifstmt;
struct forstmt;

/* expressions */
struct bin;
struct ass;
struct cmp;
struct num;
struct ref;
struct deref;
struct addrof;
struct call;
struct str_lit;


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
	virtual void visit_vardec(vardec &s) = 0;
	virtual void visit_argdec(argdec &s) = 0;
	virtual void visit_fundec(fundec &s) = 0;
	virtual void visit_sexp(sexp &s) = 0;
	virtual void visit_ret(ret &s) = 0;
	virtual void visit_ifstmt(ifstmt &s) = 0;
	virtual void visit_forstmt(forstmt &s) = 0;

	/* expressions */
	virtual void visit_bin(bin &e) = 0;
	virtual void visit_ass(ass &e) = 0;
	virtual void visit_cmp(cmp &e) = 0;
	virtual void visit_num(num &e) = 0;
	virtual void visit_ref(ref &e) = 0;
	virtual void visit_deref(deref &e) = 0;
	virtual void visit_addrof(addrof &e) = 0;
	virtual void visit_call(call &e) = 0;
	virtual void visit_str_lit(str_lit &e) = 0;
};
