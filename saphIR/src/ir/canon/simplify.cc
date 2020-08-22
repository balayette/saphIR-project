#include "ir/canon/simplify.hh"
#include "ir/visitors/ir-cloner-visitor.hh"

namespace ir
{
class and_or_simplifier : public ir_cloner_visitor
{
      public:
	and_or_simplifier(mach::target &target) : ir_cloner_visitor(target) {}

	virtual void visit_binop(tree::binop &b) override
	{
		ir_cloner_visitor::visit_binop(b);
		auto bin = ret_.as<tree::binop>();
		auto left = bin->lhs();
		auto right = bin->rhs();

		auto op = bin->op();
		if (op != ops::binop::AND && op != ops::binop::OR)
			return;

		if (op == ops::binop::AND) {
			// e1 && e2 is a special case, which gets translated to
			// if (e1 == 0)
			//      0
			// else
			//      e2 != 0
			//
			// e1 == 0, f_label, t_label
			// t_label:
			// result = e2 != 0
			// jmp done_label
			// f_label:
			// result = 0
			// done_label:
			utils::temp result;
			utils::label f_label, t_label, t2_label, done_label;

			utils::ref<tree::meta_cx> cond1 =
				new tree::meta_cx(target_, ops::cmpop::EQ, left,
						  target_.make_cnst(0));
			utils::ref<tree::meta_cx> cond2 =
				new tree::meta_cx(target_, ops::cmpop::NEQ,
						  right, target_.make_cnst(0));

			auto seq = target_.make_seq({
				cond1->un_cx(f_label, t_label),
				target_.make_label(t_label),
				target_.move_ext(
					target_.make_temp(
						result, target_.integer_type()),
					cond2->un_ex()),
				target_.make_jump(target_.make_name(done_label),
						  {done_label}),
				target_.make_label(f_label),
				target_.move_ext(
					target_.make_temp(
						result, target_.integer_type()),
					target_.make_cnst(0)),
				target_.make_label(done_label),
			});

			ret_ = target_.make_eseq(
				seq, target_.make_temp(result,
						       target_.integer_type()));
		} else {
			/*
			 * e1 || e2 is a special case, which gets translated to
			 * if (e1 == 1)
			 *      1
			 * else
			 *      e1 == 1
			 *
			 * result = e1 == 1
			 * result == 1, done_label, f_label
			 * f_label:
			 * result = e2 == 1
			 * done_label:
			 */

			utils::temp result;
			utils::label f_label, done_label;

			utils::ref<tree::meta_cx> cond1 =
				new tree::meta_cx(target_, ops::cmpop::EQ, left,
						  target_.make_cnst(1));
			utils::ref<tree::meta_cx> cond2 = new tree::meta_cx(
				target_, ops::cmpop::EQ,
				target_.make_temp(result,
						  target_.integer_type()),
				target_.make_cnst(1));
			utils::ref<tree::meta_cx> cond3 =
				new tree::meta_cx(target_, ops::cmpop::EQ,
						  right, target_.make_cnst(1));

			auto seq = target_.make_seq({
				target_.move_ext(
					target_.make_temp(
						result, target_.integer_type()),
					cond1->un_ex()),
				cond2->un_cx(done_label, f_label),
				target_.make_label(f_label),
				target_.move_ext(
					target_.make_temp(
						result, target_.integer_type()),
					cond3->un_ex()),
				target_.make_label(done_label),
			});

			ret_ = target_.make_eseq(
				seq, target_.make_temp(result,
						       target_.integer_type()));
		}
	}
};

tree::rnode simplify(tree::rnode tree)
{
	and_or_simplifier s(tree->target());
	return s.perform(tree);
}
} // namespace ir
