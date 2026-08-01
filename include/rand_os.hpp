#pragma once

/**
 * rand_os.hpp — 操作系统级密码学安全随机源
 *
 * 统一封装平台随机源：
 *   - Windows: BCryptGenRandom (BCRYPT_USE_SYSTEM_PREFERRED_RNG)
 *   - Linux/POSIX: /dev/urandom
 *
 * 返回 true 表示成功填满 out[0..len)。
 */
#include <cstdint>
#include <cstddef>

namespace jpssl {

bool os_rand_bytes(uint8_t* out, size_t len);

}
