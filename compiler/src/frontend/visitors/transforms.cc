#include "frontend/visitors/transforms.hh"
#include "utils/symbol.hh"

namespace frontend::transforms
{
void unique_ids_visitor::visit_locdec(locdec &s)
{
	s.name_ = make_unique(s.name_);
	default_visitor::visit_locdec(s);
}
} // namespace frontend::transforms
