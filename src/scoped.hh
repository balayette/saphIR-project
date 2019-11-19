#pragma once

#include <stack>
#include <unordered_map>

template <typename K, typename V> class scoped_map
{
	using map_type = std::unordered_map<K, V>;

      public:
	scoped_map() { scopes_.emplace(); }

	void new_scope() { scopes_.emplace(scopes_.top()); }

	void end_scope() { scopes_.pop(); }

	bool add(const K &k, V v)
	{
		auto [_, inserted] = scopes_.top().emplace(k, v);
		return inserted;
	}

	std::optional<V> get(const K &k)
	{
		auto ret = scopes_.top().find(k);
		if (ret == scopes_.top().end())
			return std::nullopt;
		return ret->second;
	}

      private:
	std::stack<map_type> scopes_;
};

template <typename T> class scoped_ptr
{
      public:
	scoped_ptr() { static_assert(std::is_pointer<T>::value); }
	void enter(T elm) { scopes_.emplace(elm); }
	void leave() { scopes_.pop(); }
	T get() { return scopes_.top(); }

	T operator->() { return scopes_.top(); }

      private:
	std::stack<T> scopes_;
};
