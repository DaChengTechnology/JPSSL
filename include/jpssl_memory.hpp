#pragma once
/**
 * jpssl_memory.hpp -- jpssl::make_unique 兼容层
 *
 * C++14 起直接复用 std::make_unique（零开销别名）；
 * C++11 提供行为等价的自实现（仅非数组重载，覆盖本项目用法）。
 */

#include <memory>
#include <utility>

// 使用语言版本而非特性测试宏：MSVC 在 C++11 模式下也会定义
// __cpp_lib_make_unique，导致错误地 using std::make_unique。
#if defined(_MSVC_LANG)
#define JPSSL_MEMORY_CPLUSPLUS _MSVC_LANG
#else
#define JPSSL_MEMORY_CPLUSPLUS __cplusplus
#endif

#if JPSSL_MEMORY_CPLUSPLUS >= 201402L

namespace jpssl {

using std::make_unique;

} // namespace jpssl

#else

namespace jpssl {

template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

} // namespace jpssl

#undef JPSSL_MEMORY_CPLUSPLUS

#endif
