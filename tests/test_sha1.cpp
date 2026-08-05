#include "sha1.hpp"

#include "cpu_features.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#ifdef JPSSL_TEST_OPENSSL
#include <openssl/sha.h>
#endif

using namespace jpssl;

static int failures = 0;
#define TEST(name, cond)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL: %s\n", name);                          \
            failures++;                                                        \
        } else {                                                               \
            std::printf("PASS: %s\n", name);                                   \
        }                                                                      \
    } while (0)

static std::string hex20(const uint8_t d[20]) {
    char b[41];
    for (int i = 0; i < 20; ++i) std::sprintf(b + i * 2, "%02x", d[i]);
    return {b};
}

static std::vector<uint8_t> random_bytes(size_t n, uint32_t seed) {
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = (uint8_t)(rng() & 0xff);
    return v;
}

static void test_known_vectors() {
    // FIPS 180-4 / NIST SHA-1 test vectors.
    struct Vec { const char* name; const char* msg; size_t len; const char* hex; };
    static const Vec vecs[] = {
        {"SHA-1('')", "", 0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"SHA-1('abc')", "abc", 3, "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"SHA-1(two-block msg)", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
         "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"SHA-1(fox)", "The quick brown fox jumps over the lazy dog", 43,
         "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
    };
    for (const auto& v : vecs) {
        uint8_t d[20];
        sha1((const uint8_t*)v.msg, v.len, d);
        TEST(v.name, hex20(d) == v.hex);
    }

    // 1,000,000 x 'a'.
    std::string big(1000000, 'a');
    uint8_t d[20];
    sha1((const uint8_t*)big.data(), big.size(), d);
    TEST("SHA-1(1M 'a')", hex20(d) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

static void test_incremental() {
    const std::string msg = "The quick brown fox jumps over the lazy dog";
    uint8_t full[20], part[20];
    sha1((const uint8_t*)msg.data(), msg.size(), full);

    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)msg.data(), 10);
    sha1_update(&ctx, (const uint8_t*)msg.data() + 10, msg.size() - 10);
    sha1_final(&ctx, part);
    TEST("SHA-1 incremental update", std::memcmp(full, part, 20) == 0);

    // Byte-by-byte incremental must match too.
    sha1_init(&ctx);
    for (char c : msg) sha1_update(&ctx, (const uint8_t*)&c, 1);
    sha1_final(&ctx, part);
    TEST("SHA-1 byte-at-a-time update", std::memcmp(full, part, 20) == 0);
}

/// Hash one message with the reference scalar path.
static std::vector<uint8_t> ref_hash(const uint8_t* data, size_t len) {
    std::vector<uint8_t> d(20);
    sha1(data, len, d.data());
    return d;
}

static bool msgs_equal(const std::vector<uint8_t>& a, const uint8_t* b) {
    return a.size() == 20 && std::memcmp(a.data(), b, 20) == 0;
}

static void test_multi_buffers() {
    const size_t lens[] = {0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33,
                           55, 56, 57, 63, 64, 65, 119, 120, 121,
                           127, 128, 129, 256, 1000, 4096};

    const bool have_avx2 = cpu_has_avx2();
    const bool have_avx512 = cpu_has_avx512bw();
    std::printf("CPU features: AVX2=%d AVX512BW=%d\n", (int)have_avx2, (int)have_avx512);

    uint32_t seed = 0xC0FFEE;
    for (size_t len : lens) {
        const uint8_t* msgs8[8];
        const uint8_t* msgs16[16];
        std::vector<std::vector<uint8_t>> data;
        for (int m = 0; m < 16; ++m) {
            data.push_back(random_bytes(len, seed + (uint32_t)m * 7919));
            if (m < 8) msgs8[m] = data[m].data();
            msgs16[m] = data[m].data();
        }

        if (have_avx2) {
            uint8_t out8[8][20];
            sha1_multi_avx2(msgs8, len, out8);
            bool ok = true;
            for (int m = 0; m < 8; ++m)
                ok = ok && msgs_equal(ref_hash(msgs8[m], len), out8[m]);
            TEST(("SHA-1 AVX2 8-way len=" + std::to_string(len)).c_str(), ok);
        }
        if (have_avx512) {
            uint8_t out16[16][20];
            sha1_multi_avx512(msgs16, len, out16);
            bool ok = true;
            for (int m = 0; m < 16; ++m)
                ok = ok && msgs_equal(ref_hash(msgs16[m], len), out16[m]);
            TEST(("SHA-1 AVX-512 16-way len=" + std::to_string(len)).c_str(), ok);
        }
    }
}

static void test_batch_dispatch() {
    const size_t lens[] = {0, 1, 55, 56, 57, 63, 64, 65, 127, 128, 129, 500};
    const size_t counts[] = {1, 2, 3, 7, 8, 9, 15, 16, 17, 20};
    uint32_t seed = 0x5EED;
    for (size_t len : lens) {
        for (size_t count : counts) {
            std::vector<std::vector<uint8_t>> data;
            std::vector<const uint8_t*> ptrs;
            for (size_t m = 0; m < count; ++m) {
                data.push_back(random_bytes(len, seed + (uint32_t)m * 104729));
                ptrs.push_back(data[m].data());
            }
            std::vector<uint8_t> outs(count * 20);
            sha1_batch(ptrs.data(), len, outs.data(), count);
            bool ok = true;
            for (size_t m = 0; m < count; ++m)
                ok = ok && msgs_equal(ref_hash(ptrs[m], len), outs.data() + m * 20);
            TEST(("SHA-1 batch count=" + std::to_string(count) + " len=" + std::to_string(len)).c_str(), ok);
        }
    }
}

#ifdef JPSSL_TEST_OPENSSL
static void test_openssl_compare() {
    const size_t lens[] = {0, 1, 3, 20, 55, 56, 57, 63, 64, 65, 100, 1000, 65537};
    uint32_t seed = 0xABCD;
    bool ok = true;
    for (size_t len : lens) {
        const auto data = random_bytes(len, seed);
        uint8_t ours[20], theirs[SHA_DIGEST_LENGTH];
        sha1(data.data(), len, ours);
        SHA1(data.data(), len, theirs);
        if (std::memcmp(ours, theirs, 20) != 0) {
            std::fprintf(stderr, "OpenSSL mismatch at len=%zu\n", len);
            ok = false;
        }
    }
    TEST("SHA-1 vs OpenSSL (random lengths)", ok);
}
#endif

int main() {
    test_known_vectors();
    test_incremental();
    test_multi_buffers();
    test_batch_dispatch();
#ifdef JPSSL_TEST_OPENSSL
    test_openssl_compare();
#endif
    if (failures == 0) std::printf("All SHA-1 tests passed.\n");
    else std::fprintf(stderr, "%d SHA-1 test(s) FAILED.\n", failures);
    return failures ? 1 : 0;
}
