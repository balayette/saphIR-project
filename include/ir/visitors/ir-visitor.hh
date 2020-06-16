#pragma once

namespace ir
{
namespace tree
{
struct cnst;
struct braceinit;
struct name;
struct temp;
struct binop;
struct unaryop;
struct mem;
struct call;
struct eseq;
struct move;
struct sexp;
struct jump;
struct cjump;
struct seq;
struct label;
} // namespace tree

class ir_visitor
{
      public:
	virtual void visit_cnst(tree::cnst &n) = 0;
	virtual void visit_braceinit(tree::braceinit &n) = 0;
	virtual void visit_name(tree::name &n) = 0;
	virtual void visit_temp(tree::temp &n) = 0;
	virtual void visit_binop(tree::binop &n) = 0;
	virtual void visit_unaryop(tree::unaryop &n) = 0;
	virtual void visit_mem(tree::mem &n) = 0;
	virtual void visit_call(tree::call &n) = 0;
	virtual void visit_eseq(tree::eseq &n) = 0;
	virtual void visit_move(tree::move &n) = 0;
	virtual void visit_sexp(tree::sexp &n) = 0;
	virtual void visit_jump(tree::jump &n) = 0;
	virtual void visit_cjump(tree::cjump &n) = 0;
	virtual void visit_seq(tree::seq &n) = 0;
	virtual void visit_label(tree::label &n) = 0;
};
} // namespace ir
