#pragma once
/**
 * jpssl_optional.hpp -- jpssl::optional 兼容层
 *
 * C++17 起直接复用 std::optional（零开销别名）；
 * C++14（及 C++11）提供行为兼容的最小自实现，
 * 覆盖本项目使用的接口：默认/值/nullopt 构造、拷贝与移动、
 * operator bool / has_value / value / value_or / operator* /
 * operator-> / reset / emplace / make_optional。
 */

#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

// 使用语言版本而非特性测试宏，避免 MSVC 在低标准模式下误判。
#if defined(_MSVC_LANG)
#define JPSSL_OPTIONAL_CPLUSPLUS _MSVC_LANG
#else
#define JPSSL_OPTIONAL_CPLUSPLUS __cplusplus
#endif

#if JPSSL_OPTIONAL_CPLUSPLUS >= 201703L

#include <optional>

namespace jpssl {

using std::optional;
using std::nullopt;
using std::nullopt_t;
using std::make_optional;
using std::bad_optional_access;

} // namespace jpssl

#undef JPSSL_OPTIONAL_CPLUSPLUS

#else

namespace jpssl {

struct nullopt_t {
    explicit constexpr nullopt_t(int) noexcept {}
};
constexpr nullopt_t nullopt{0};

class bad_optional_access : public std::logic_error {
public:
    bad_optional_access() : std::logic_error("bad optional access") {}
};

template <typename T>
class optional {
public:
    using value_type = T;

    optional() noexcept : has_(false) {}
    optional(nullopt_t) noexcept : has_(false) {}

    optional(const optional& o) : has_(false) {
        if (o.has_) construct(o.value());
    }
    optional(optional&& o) noexcept(
        std::is_nothrow_move_constructible<T>::value)
        : has_(false) {
        if (o.has_) construct(std::move(o.value()));
    }

    optional(const T& v) : has_(false) { construct(v); }
    optional(T&& v) : has_(false) { construct(std::move(v)); }

    template <typename U,
              typename std::enable_if<
                  std::is_constructible<T, U&&>::value &&
                  !std::is_same<typename std::decay<U>::type,
                                optional>::value,
                  int>::type = 0>
    optional(U&& v) : has_(false) {
        construct(std::forward<U>(v));
    }

    ~optional() { reset(); }

    optional& operator=(nullopt_t) noexcept {
        reset();
        return *this;
    }
    optional& operator=(const optional& o) {
        if (o.has_) *this = o.value();
        else reset();
        return *this;
    }
    optional& operator=(optional&& o) noexcept(
        std::is_nothrow_move_assignable<T>::value &&
        std::is_nothrow_move_constructible<T>::value) {
        if (o.has_) *this = std::move(o.value());
        else reset();
        return *this;
    }
    optional& operator=(const T& v) {
        if (has_) *ptr() = v;
        else construct(v);
        return *this;
    }
    optional& operator=(T&& v) {
        if (has_) *ptr() = std::move(v);
        else construct(std::move(v));
        return *this;
    }

    explicit operator bool() const noexcept { return has_; }
    bool has_value() const noexcept { return has_; }

    T& value() & {
        if (!has_) throw bad_optional_access();
        return *ptr();
    }
    const T& value() const & {
        if (!has_) throw bad_optional_access();
        return *ptr();
    }
    T&& value() && {
        if (!has_) throw bad_optional_access();
        return std::move(*ptr());
    }

    template <typename U>
    T value_or(U&& default_value) const& {
        return has_ ? *ptr() : static_cast<T>(std::forward<U>(default_value));
    }

    T& operator*() & noexcept { return *ptr(); }
    const T& operator*() const & noexcept { return *ptr(); }
    T&& operator*() && noexcept { return std::move(*ptr()); }

    T* operator->() noexcept { return ptr(); }
    const T* operator->() const noexcept { return ptr(); }

    void reset() noexcept {
        if (has_) {
            ptr()->~T();
            has_ = false;
        }
    }

    template <typename... Args>
    T& emplace(Args&&... args) {
        reset();
        construct(std::forward<Args>(args)...);
        return *ptr();
    }

private:
    T* ptr() noexcept { return reinterpret_cast<T*>(&storage_); }
    const T* ptr() const noexcept {
        return reinterpret_cast<const T*>(&storage_);
    }

    template <typename... Args>
    void construct(Args&&... args) {
        ::new (static_cast<void*>(&storage_))
            T(std::forward<Args>(args)...);
        has_ = true;
    }

    // 自实现对齐存储：避免 MSVC 对扩展对齐使用 std::aligned_storage
    // 时的静态断言（C++14 模式）。
    struct storage_type {
        alignas(T) unsigned char data[sizeof(T)];
    };
    storage_type storage_;
    bool has_;
};

template <typename T>
optional<typename std::decay<T>::type> make_optional(T&& v) {
    return optional<typename std::decay<T>::type>(std::forward<T>(v));
}

} // namespace jpssl

#endif
