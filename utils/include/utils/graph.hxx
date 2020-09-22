#pragma once

#include "utils/graph.hh"
#include <algorithm>

namespace utils
{
template <typename T> gnode<T>::gnode(T value) : elm_(value) {}
template <typename T> T &gnode<T>::operator*() { return elm_; }
template <typename T> T *gnode<T>::operator->() { return &elm_; }

template <typename T> const T &gnode<T>::operator*() const { return elm_; }
template <typename T> const T *gnode<T>::operator->() const { return &elm_; }

template <typename T> node_id graph<T>::add_node(T value)
{
	nodes_.emplace_back(value);
	return nodes_.size() - 1;
}

template <typename T> node_id graph<T>::get_or_insert(T value)
{
	auto found = std::find_if(
		nodes_.begin(), nodes_.end(),
		[&](const auto &gnode) { return gnode.elm_ == value; });
	if (found != nodes_.end())
		return std::distance(nodes_.begin(), found);
	return add_node(value);
}

template <typename T> void graph<T>::add_edge(node_id n1, node_id n2)
{
	if (n1 == n2)
		return;

	auto &succs = nodes_[n1].succs();
	auto &preds = nodes_[n2].preds();

	if (std::find(succs.begin(), succs.end(), n2) != succs.end())
		return;

	succs.emplace_back(n2);
	preds.emplace_back(n1);
}

template <typename T> T *graph<T>::get(node_id idx)
{
	if (nodes_.size() <= idx)
		return nullptr;
	return &(nodes_[idx].elm_);
}

template <typename T> const T *graph<T>::get(node_id idx) const
{
	if (nodes_.size() <= idx)
		return nullptr;
	return &(nodes_[idx].elm_);
}

template <typename T>
void graph<T>::dump_dot(std::ostream &os, bool directed) const
{
	if (directed)
		os << "digraph {\n";
	else
		os << "graph {\n";
	for (node_id i = 0; i < nodes_.size(); i++) {
		os << '"' << i << "\" ";
		// XXX: Add dot dumpers to classes.
		os << *nodes_[i] << ";\n";
		for (auto s : nodes_[i].succs()) {
			os << '"' << i << "\"";
			if (directed)
				os << " -> ";
			else
				os << " -- ";
			os << "\"" << s << "\";\n";
		}
	}
	os << "}\n";
}

template <typename T> size_t graph<T>::size() const { return nodes_.size(); }

template <typename T> std::vector<T> graph<T>::values() const
{
	std::vector<T> ret;
	for (auto &n : nodes_)
		ret.push_back(*n);
	return ret;
}
} // namespace utils
