#pragma once

struct bin;
struct num;
struct seq;
struct id;
struct fun;

class visitor
{
      public:
	virtual void visit_bin(bin &e) = 0;
	virtual void visit_num(num &e) = 0;
	virtual void visit_seq(seq &e) = 0;
	virtual void visit_id(id &e) = 0;
	virtual void visit_fun(fun& e) = 0;
};
