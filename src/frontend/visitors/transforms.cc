#include "frontend/visitors/transforms.hh"
#include "utils/symbol.hh"

namespace frontend::transforms
{
void unique_ids_visitor::visit_argdec(argdec &s)
{
	s.name_ = make_unique(s.name_);
	default_visitor::visit_argdec(s);
}

void unique_ids_visitor::visit_vardec(vardec &s)
{
	s.name_ = make_unique(s.name_);
	default_visitor::visit_vardec(s);
}
} // namespace frontend::transforms
