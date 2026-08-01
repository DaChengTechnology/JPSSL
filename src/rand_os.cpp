// rand_os.cpp — 操作系统级密码学安全随机源（Windows BCrypt / POSIX urandom）
#include "rand_os.hpp"

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <cstdio>
#endif

namespace jpssl {

bool os_rand_bytes(uint8_t* out, size_t len) {
    if (!out) return len == 0;
    if (len == 0) return true;
#ifdef _WIN32
    // Windows: BCryptGenRandom，系统首选 CSPRNG。
    // len 上限 ULONG_MAX（约 4 GiB），密码学用途的密钥/IV/nonce 远小于此。
    return BCryptGenRandom(nullptr, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t n = std::fread(out, 1, len, f);
    std::fclose(f);
    return n == len;
#endif
}

} // namespace jpssl
