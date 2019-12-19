#pragma once

#include "utils/graph.hh"
#include <algorithm>

namespace utils
{
template <typename T> gnode<T>::gnode(T value) : elm_(value) {}
template <typename T> T &gnode<T>::operator*() { return elm_; }
template <typename T> T *gnode<T>::operator->() { return &elm_; }

template <typename T> unsigned graph<T>::add_node(T value)
{
	nodes_.emplace_back(value);
	return nodes_.size() - 1;
}

template <typename T> void graph<T>::add_edge(unsigned n1, unsigned n2)
{
	auto &succs = nodes_[n1].succ_;
	auto &preds = nodes_[n2].pred_;

	succs.emplace_back(n2);
	preds.emplace_back(n1);
}

template <typename T> T *graph<T>::get(unsigned idx)
{
	if (nodes_.size() <= idx)
		return nullptr;
	return &nodes_[idx];
}

template <typename T> void graph<T>::dump_dot(std::ostream &os)
{
	os << "digraph {\n";
	for (unsigned i = 0; i < nodes_.size(); i++) {
		os << '"' << i << '"';
                // XXX: Add dot dumpers to classes.
		os << *nodes_[i] << "\n";
		for (auto s : nodes_[i].succ_)
			os << '"' << i << "\" -> \"" << s << "\";\n";
	}
	os << "}\n";
}
} // namespace utils
