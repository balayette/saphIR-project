#pragma once

#include <vector>
#include <iostream>

namespace utils
{
template <typename T> struct gnode {
	gnode(T value);
	T &operator*();
	T *operator->();

	T elm_;
	std::vector<unsigned> pred_;
	std::vector<unsigned> succ_;
};

using node_id = size_t;

template <typename T> class graph
{
      public:
	node_id add_node(T value);
	void add_edge(node_id n1, node_id n2);
	T *get(node_id idx);
	void dump_dot(std::ostream &os);

      private:
	std::vector<gnode<T>> nodes_;
};
} // namespace utils

#include "graph.hxx"
