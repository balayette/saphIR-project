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

template <typename T> class graph
{
      public:
	unsigned add_node(T value);
	void add_edge(unsigned n1, unsigned n2);
	T *get(unsigned idx);
        void dump_dot(std::ostream& os);

      private:
	std::vector<gnode<T>> nodes_;
};
} // namespace utils

#include "graph.hxx"
