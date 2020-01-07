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

void unique_ids_visitor::visit_globaldec(globaldec &s)
{
	s.name_ = unique_label(s.name_.get() + "_global");
	default_visitor::visit_globaldec(s);
}
} // namespace frontend::transforms
