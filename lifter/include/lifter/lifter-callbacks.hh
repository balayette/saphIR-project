#pragma once
#include "ir/visitors/ir-cloner-visitor.hh"

namespace lifter
{
class lifter_callbacks : public ir::ir_cloner_visitor
{
      public:
	lifter_callbacks(mach::target &target, ir::tree::rexp write_callback,
			 ir::tree::rexp read_callback, void *data)
	    : ir::ir_cloner_visitor(target), write_callback_(write_callback),
	      read_callback_(read_callback), data_(reinterpret_cast<uintptr_t>(data))
	{
	}

	virtual void visit_move(ir::tree::move &) override;

	void set_write_callback(ir::tree::rexp e) { write_callback_ = e; }
	void set_read_callback(ir::tree::rexp e) { read_callback_ = e; }

      private:
	ir::tree::rnode write_callback(utils::ref<ir::tree::move> mv);
	ir::tree::rnode read_callback(utils::ref<ir::tree::move> mv);

	ir::tree::rexp write_callback_;
	ir::tree::rexp read_callback_;

	uintptr_t data_;
};
} // namespace lifter
