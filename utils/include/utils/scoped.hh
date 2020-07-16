#pragma once

#include <stack>
#include <unordered_map>
#include <utility>

namespace utils
{
template <typename T> class scoped_var
{
	using element_type = T;

      public:
	void enter(T elm) { scopes_.emplace(elm); }
	void leave() { scopes_.pop(); }
	T get() { return scopes_.top(); }
	operator T() { return scopes_.top(); }

      private:
	std::stack<T> scopes_;
};

template <typename T> class scoped_ptr : public scoped_var<T>
{
      public:
	scoped_ptr() { static_assert(std::is_pointer<T>::value); }

	T operator->() { return this->get(); }
};

/* Different signatures from scoped_var because different behavior */
template <typename K, typename V> class scoped_map
{
	using map_type = std::unordered_map<K, V>;

      public:
	scoped_map();

	void new_scope();

	void end_scope();

	bool add(const K &k, V v);

	std::optional<V> get(const K &k);

	size_t size() const;

      private:
	std::stack<map_type> scopes_;
};
} // namespace utils

#include "scoped.hxx"
