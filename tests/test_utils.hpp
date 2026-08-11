#pragma once

/**
 * @file test_utils.hpp
 * @brief 轻量级 C++ 测试基础设施（header-only）
 *
 * 提供 TEST / TEST_MSG / TEST_NEAR / TEST_THROWS 宏、
 * 测试注册器、运行器和汇总输出。仅依赖 C++ 标准库。
 *
 * 用法：
 *   #include "test_utils.hpp"
 *
 *   void my_tests() {
 *       TEST("basic arithmetic", 1 + 1 == 2);
 *       TEST_MSG("division", 4 / 2 == 2, "expected 2");
 *       TEST_NEAR("float compare", 3.14, 3.15, 0.02);
 *       TEST_THROWS("out_of_range", vec.at(999), std::out_of_range);
 *   }
 *
 *   int main() {
 *       RUN_TEST(my_tests);
 *       return test_summary();
 *   }
 */

#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <cmath>
#include <cstdlib>

namespace jptest {

// ================================================================
// 全局测试计数器
// ================================================================

/// 通过的断言数
static int g_pass = 0;

/// 失败的断言数
static int g_fail = 0;

/// 最近一次失败断言的消息
static std::string g_last_fail_msg;

// ================================================================
// 测试注册器
// ================================================================

/// 一个测试用例：名称 + 可调用体
struct TestCase {
    std::string name;
    std::function<void()> func;
};

/// 全局测试注册表（惰性初始化）
inline std::vector<TestCase>& test_registry() {
    static std::vector<TestCase> registry;
    return registry;
}

/// 注册一个测试用例
inline void register_test(const std::string& suite, const std::string& name,
                           std::function<void()> func) {
    test_registry().push_back({suite + "::" + name, std::move(func)});
}

} // namespace jptest

// ================================================================
// 测试断言宏
// ================================================================

#ifndef TEST
#define TEST(name, expr) do { \
    if (!(expr)) { \
        std::cerr << "  \u2717 " << name << " (line " << __LINE__ << ")" << std::endl; \
        ::jptest::g_fail++; \
        ::jptest::g_last_fail_msg = name; \
    } else { \
        std::cout << "  \u2713 " << name << std::endl; \
        ::jptest::g_pass++; \
    } \
} while(0)
#endif

#ifndef TEST_MSG
#define TEST_MSG(name, expr, msg) do { \
    if (!(expr)) { \
        std::cerr << "  \u2717 " << name << ": " << msg << " (line " << __LINE__ << ")" << std::endl; \
        ::jptest::g_fail++; \
        ::jptest::g_last_fail_msg = name; \
    } else { \
        std::cout << "  \u2713 " << name << std::endl; \
        ::jptest::g_pass++; \
    } \
} while(0)
#endif

/// 近似浮点比较
#ifndef TEST_NEAR
#define TEST_NEAR(name, a, b, eps) TEST(name, std::abs((a) - (b)) <= (eps))
#endif

/// 预期抛出异常
#ifndef TEST_THROWS
#define TEST_THROWS(name, expr, ex_type) do { \
    bool caught = false; \
    try { expr; } \
    catch (const ex_type&) { caught = true; } \
    catch (...) {} \
    TEST(name, caught); \
} while(0)
#endif

// ================================================================
// 测试运行器
// ================================================================

/**
 * @brief 运行单个测试套件
 */
#define RUN_TEST(suite_func) do { \
    std::cout << "\n=== " << #suite_func << " ===" << std::endl; \
    suite_func(); \
} while(0)

/**
 * @brief 打印测试汇总结果，返回 0（全通过）或 1（有失败）。
 */
inline int test_summary() {
    std::cout << "\n================================================" << std::endl;
    std::cout << "  Result: " << jptest::g_pass
              << " passed, " << jptest::g_fail << " failed"
              << (jptest::g_fail == 0 ? " \u2713" : " \u2717") << std::endl;
    std::cout << "================================================" << std::endl;
    return jptest::g_fail > 0 ? 1 : 0;
}

// ================================================================
// 辅助工具
// ================================================================

/// 字节数组十六进制转储
inline std::string hex_dump(const uint8_t* d, size_t n) {
    std::ostringstream oss;
    oss << std::hex;
    for (size_t i = 0; i < n; ++i) {
        if (i > 0) oss << " ";
        oss << std::setw(2) << std::setfill('0') << (int)d[i];
    }
    return oss.str();
}

/// 字符串十六进制转储
inline std::string hex_dump(const std::string& s) {
    return hex_dump(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
