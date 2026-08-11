#include "test_utils.hpp"

#include "base64.hpp"
#include "base64_internal.hpp"
#include "cpu_features.hpp"

#include <cstdint>
#include <random>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jptest;

static std::vector<uint8_t> random_bytes(size_t n, uint32_t seed) {
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = (uint8_t)(rng() & 0xff);
    return v;
}

static bool dec_eq(const std::string& s, const std::vector<uint8_t>& expect) {
    auto r = base64_decode(s);
    return r.has_value() && *r == expect;
}

// RFC 4648 section 10 test vectors.
static void test_rfc_vectors() {
    const std::vector<uint8_t> f = {(uint8_t)'f'};
    const std::vector<uint8_t> fo = {(uint8_t)'f', (uint8_t)'o'};
    const std::vector<uint8_t> foo = {(uint8_t)'f', (uint8_t)'o', (uint8_t)'o'};
    const std::vector<uint8_t> foob = {(uint8_t)'f', (uint8_t)'o', (uint8_t)'o', (uint8_t)'b'};
    const std::vector<uint8_t> fooba = {(uint8_t)'f', (uint8_t)'o', (uint8_t)'o', (uint8_t)'b', (uint8_t)'a'};
    const std::vector<uint8_t> foobar = {(uint8_t)'f', (uint8_t)'o', (uint8_t)'o', (uint8_t)'b', (uint8_t)'a', (uint8_t)'r'};

    TEST("RFC 4648: encode ''", base64_encode(std::vector<uint8_t>{}) == "");
    TEST("RFC 4648: encode 'f'", base64_encode(f) == "Zg==");
    TEST("RFC 4648: encode 'fo'", base64_encode(fo) == "Zm8=");
    TEST("RFC 4648: encode 'foo'", base64_encode(foo) == "Zm9v");
    TEST("RFC 4648: encode 'foob'", base64_encode(foob) == "Zm9vYg==");
    TEST("RFC 4648: encode 'fooba'", base64_encode(fooba) == "Zm9vYmE=");
    TEST("RFC 4648: encode 'foobar'", base64_encode(foobar) == "Zm9vYmFy");

    TEST("RFC 4648: decode ''", dec_eq("", {}));
    TEST("RFC 4648: decode 'Zg=='", dec_eq("Zg==", f));
    TEST("RFC 4648: decode 'Zm8='", dec_eq("Zm8=", fo));
    TEST("RFC 4648: decode 'Zm9v'", dec_eq("Zm9v", foo));
    TEST("RFC 4648: decode 'Zm9vYg=='", dec_eq("Zm9vYg==", foob));
    TEST("RFC 4648: decode 'Zm9vYmE='", dec_eq("Zm9vYmE=", fooba));
    TEST("RFC 4648: decode 'Zm9vYmFy'", dec_eq("Zm9vYmFy", foobar));

    // Padding-less trailing group is accepted.
    TEST("RFC 4648: decode unpadded", dec_eq("QUJD", {'A', 'B', 'C'}));
}

// Round trips across all short lengths (exercises every SIMD tail boundary)
// plus a few large multi-chunk buffers.
static void test_roundtrip() {
    for (size_t len = 0; len <= 400; ++len) {
        const auto data = random_bytes(len, (uint32_t)(len * 2654435761u + 1));
        const std::string enc = base64_encode(data);
        const auto dec = base64_decode(enc);
        TEST_MSG("roundtrip len=" + std::to_string(len),
                 dec.has_value() && *dec == data, "roundtrip mismatch");
    }

    for (size_t len : {1024, 4096, 65536, 100000}) {
        const auto data = random_bytes(len, (uint32_t)(len + 12345));
        const std::string enc = base64_encode(data);
        const auto dec = base64_decode(enc);
        TEST_MSG("roundtrip len=" + std::to_string(len),
                 dec.has_value() && *dec == data, "roundtrip mismatch");
    }
}

// Cross-check the SIMD kernels directly against the scalar reference.
static void test_simd_direct() {
    const bool have_avx2 = cpu_has_avx2();
    const bool have_avx512 = cpu_has_avx512() && cpu_has_avx512bw();

    if (have_avx2) {
        for (size_t k = 1; k <= 24; ++k) {
            const size_t len = 24 * k;
            const auto data = random_bytes(len, (uint32_t)(7 * k + 1));

            std::string expect;
            expect.resize(((len + 2) / 3) * 4);
            detail::base64_encode_scalar(data.data(), len, &expect[0]);

            std::string got;
            got.resize(((len + 2) / 3) * 4);
            const size_t p = detail::base64_encode_avx2(data.data(), len, &got[0]);
            detail::base64_encode_scalar(data.data() + p, len - p, &got[0] + (p / 3) * 4);
            TEST_MSG("avx2 encode 24*k k=" + std::to_string(k),
                     got == expect, "avx2 encode mismatch");
        }

        for (size_t k = 1; k <= 16; ++k) {
            const size_t chars = 32 * k;
            const auto data = random_bytes((chars / 4) * 3, (uint32_t)(11 * k + 3));
            const std::string enc = base64_encode(data);

            std::vector<uint8_t> expect((chars / 4) * 3);
            TEST("avx2 scalar ref", detail::base64_decode_scalar(enc.data(), chars, &expect[0]));

            std::vector<uint8_t> got((chars / 4) * 3);
            const bool ok = detail::base64_decode_avx2(enc.data(), chars, &got[0]);
            TEST_MSG("avx2 decode 32*k k=" + std::to_string(k),
                     ok && got == expect, "avx2 decode mismatch");
        }

        // Invalid character must be detected inside the SIMD chunk.
        std::string bad = "AB!D";
        bad.append(28, 'A');
        std::vector<uint8_t> tmp(24);
        TEST("avx2 decode invalid char", !detail::base64_decode_avx2(bad.data(), 32, tmp.data()));
    }

    if (have_avx512) {
        for (size_t k = 1; k <= 16; ++k) {
            const size_t len = 48 * k;
            const auto data = random_bytes(len, (uint32_t)(17 * k + 5));

            std::string expect;
            expect.resize(((len + 2) / 3) * 4);
            detail::base64_encode_scalar(data.data(), len, &expect[0]);

            std::string got;
            got.resize(((len + 2) / 3) * 4);
            const size_t p = detail::base64_encode_avx512(data.data(), len, &got[0]);
            detail::base64_encode_scalar(data.data() + p, len - p, &got[0] + (p / 3) * 4);
            TEST_MSG("avx512 encode 48*k k=" + std::to_string(k),
                     got == expect, "avx512 encode mismatch");
        }

        for (size_t k = 1; k <= 12; ++k) {
            const size_t chars = 64 * k;
            const auto data = random_bytes((chars / 4) * 3, (uint32_t)(23 * k + 9));
            const std::string enc = base64_encode(data);

            std::vector<uint8_t> expect((chars / 4) * 3);
            TEST("avx512 scalar ref", detail::base64_decode_scalar(enc.data(), chars, &expect[0]));

            std::vector<uint8_t> got((chars / 4) * 3);
            const bool ok = detail::base64_decode_avx512(enc.data(), chars, &got[0]);
            TEST_MSG("avx512 decode 64*k k=" + std::to_string(k),
                     ok && got == expect, "avx512 decode mismatch");
        }

        std::string bad = "AB!D";
        bad.append(60, 'A');
        std::vector<uint8_t> tmp(48);
        TEST("avx512 decode invalid char", !detail::base64_decode_avx512(bad.data(), 64, tmp.data()));
    }
}

// Invalid / non-canonical inputs must be rejected.
static void test_invalid() {
    TEST("reject odd length", !base64_decode("abc").has_value());
    TEST("reject bad char", !base64_decode("AB*D").has_value());
    TEST("reject whitespace", !base64_decode("AB D").has_value());
    TEST("reject padding not last", !base64_decode("QUJD=EFG").has_value());
    TEST("reject padding in middle", !base64_decode("QUJD====").has_value());
    TEST("reject too many padding", !base64_decode("QUJDQUJD====").has_value());
    TEST("reject '=' as first char", !base64_decode("=QUJD").has_value());
}

int main() {
    RUN_TEST(test_rfc_vectors);
    RUN_TEST(test_roundtrip);
    RUN_TEST(test_simd_direct);
    RUN_TEST(test_invalid);
    return test_summary();
}
