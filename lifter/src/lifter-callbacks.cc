#include "lifter/lifter-callbacks.hh"

namespace lifter
{
void lifter_callbacks::visit_move(ir::tree::move &m)
{
	ir::ir_cloner_visitor::visit_move(m);
	auto mv = ret_.as<ir::tree::move>();

	auto lhs = mv->lhs();
	auto rhs = mv->rhs();

	auto lmem = lhs.as<ir::tree::mem>();
	auto rmem = rhs.as<ir::tree::mem>();
	auto rext = rhs.as<ir::tree::ext>();

	if (lmem && rmem)
		return;

	if (lmem && write_callback_)
		ret_ = write_callback(mv);
	else if ((rmem || (rext && rext->e().as<ir::tree::mem>()))
		 && read_callback_)
		ret_ = read_callback(mv);
}

ir::tree::rnode lifter_callbacks::write_callback(utils::ref<ir::tree::move> mv)
{
	auto dest = mv->lhs().as<ir::tree::mem>();
	auto source = mv->rhs();
	auto addr_type = dest->e()->ty();

	utils::temp addr, value, fun;

	auto move_addr = target_.make_move(
		target_.make_temp(addr, addr_type->clone()), dest->e());
	auto move_val = target_.make_move(
		target_.make_temp(value, source->ty()->clone()), source);
	auto move_fun = target_.make_move(
		target_.make_temp(fun, write_callback_->ty()->clone()),
		write_callback_);

	auto call = target_.make_call(
		target_.make_temp(fun, write_callback_->ty()->clone()),
		{
			target_.make_cnst(data_),
			target_.make_temp(addr, addr_type->clone()),
			target_.make_cnst(mv->lhs()->ty()->assem_size()),
			target_.make_temp(value, source->ty()->clone()),
		},
		write_callback_->ty()->clone());

	auto move = target_.make_move(
		target_.make_mem(
			target_.make_temp(addr, dest->e()->ty()->clone())),
		target_.make_temp(value, source->ty()->clone()));

	return target_.make_seq({
		move_fun,
		move_addr,
		move_val,
		target_.make_sexp(call),
		move,
	});
}

ir::tree::rnode lifter_callbacks::read_callback(utils::ref<ir::tree::move> mv)
{
	auto rext = mv->rhs().as<ir::tree::ext>();
	auto source = rext ? rext->e().as<ir::tree::mem>()
			   : mv->rhs().as<ir::tree::mem>();
	auto addr_type = source->e()->ty();

	utils::temp addr, fun;

	auto move_addr = target_.make_move(
		target_.make_temp(addr, addr_type->clone()), source->e());
	auto move_fun = target_.make_move(
		target_.make_temp(fun, read_callback_->ty()->clone()),
		read_callback_);

	auto call = target_.make_call(
		target_.make_temp(fun, read_callback_->ty()->clone()),
		{
			target_.make_cnst(data_),
			target_.make_temp(addr, addr_type->clone()),
			target_.make_cnst(source->ty()->assem_size()),
		},
		read_callback_->ty()->clone());


	ir::tree::rexp new_source =
		target_.make_mem(target_.make_temp(addr, addr_type->clone()));
	if (rext) {
		rext->children()[0] = new_source;
		new_source = rext;
	}

	auto move = target_.make_move(mv->lhs(), new_source);

	return target_.make_seq({
		move_fun,
		move_addr,
		target_.make_sexp(call),
		move,
	});
}
} // namespace lifter
