#include "base64.hpp"

#include "base64_internal.hpp"
#include "cpu_features.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include "jpssl_optional.hpp"
#include <string>
#include <vector>

namespace jpssl {
namespace {

const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline int b64_value(uint8_t c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/// Runtime dispatch level: 2 = AVX-512, 1 = AVX2, 0 = scalar.
int b64_level() {
    static const int level = [] {
        if (cpu_has_avx512() && cpu_has_avx512bw()) return 2;
        if (cpu_has_avx2()) return 1;
        return 0;
    }();
    return level;
}

} // namespace

namespace detail {

void base64_encode_scalar(const uint8_t* data, size_t len, char* out) {
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8 | data[i + 2];
        out[0] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[1] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[2] = B64_ALPHABET[(v >> 6) & 0x3F];
        out[3] = B64_ALPHABET[v & 0x3F];
        i += 3;
        out += 4;
    }

    size_t rem = len - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)data[i] << 16;
        out[0] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[1] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[2] = '=';
        out[3] = '=';
    } else if (rem == 2) {
        uint32_t v = (uint32_t)data[i] << 16 | (uint32_t)data[i + 1] << 8;
        out[0] = B64_ALPHABET[(v >> 18) & 0x3F];
        out[1] = B64_ALPHABET[(v >> 12) & 0x3F];
        out[2] = B64_ALPHABET[(v >> 6) & 0x3F];
        out[3] = '=';
    }
}

bool base64_decode_scalar(const char* text, size_t len, uint8_t* out) {
    for (size_t i = 0; i < len; i += 4) {
        int a = b64_value((uint8_t)text[i]);
        int b = b64_value((uint8_t)text[i + 1]);
        int c = b64_value((uint8_t)text[i + 2]);
        int d = b64_value((uint8_t)text[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return false;

        uint32_t v = (uint32_t)a << 18 | (uint32_t)b << 12 |
                     (uint32_t)c << 6 | (uint32_t)d;
        out[0] = (uint8_t)(v >> 16);
        out[1] = (uint8_t)(v >> 8);
        out[2] = (uint8_t)v;
        out += 3;
    }
    return true;
}

} // namespace detail

std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.resize(((len + 2) / 3) * 4);

    size_t i = 0;
    switch (b64_level()) {
#ifdef JP_AVX512
    case 2:
        i = detail::base64_encode_avx512(data, len, out.data());
        break;
#endif
#ifdef JP_AVX2
    case 1:
        i = detail::base64_encode_avx2(data, len, out.data());
        break;
#endif
    default:
        break;
    }

    // SIMD leaves a short tail (including any final '=' padding) for scalar.
    detail::base64_encode_scalar(data + i, len - i, out.data() + (i / 3) * 4);
    return out;
}

std::string base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

jpssl::optional<std::vector<uint8_t>> base64_decode(const std::string& text) {
    if (text.size() % 4 != 0) return jpssl::nullopt;

    const size_t n = text.size();
    std::vector<uint8_t> out;
    // Size the buffer up front: the SIMD kernels write directly into it, and
    // the scalar tail appends after shrinking back to the SIMD output count.
    out.resize((n / 4) * 3);

    size_t i = 0;
    switch (b64_level()) {
#ifdef JP_AVX512
    case 2:
        if (n >= 68) {
            // 64-char SIMD chunks; the final 4-char group (possible '=' padding)
            // is always handled by the scalar tail.
            const size_t n_simd = ((n - 4) / 64) * 64;
            if (!detail::base64_decode_avx512(text.data(), n_simd, out.data()))
                return jpssl::nullopt;
            i = n_simd;
        }
        break;
#endif
#ifdef JP_AVX2
    case 1:
        if (n >= 36) {
            const size_t n_simd = ((n - 4) / 32) * 32;
            if (!detail::base64_decode_avx2(text.data(), n_simd, out.data()))
                return jpssl::nullopt;
            i = n_simd;
        }
        break;
#endif
    default:
        break;
    }

    out.resize((i / 4) * 3);

    while (i < n) {
        int a = b64_value((uint8_t)text[i]);
        int b = b64_value((uint8_t)text[i + 1]);
        int c = text[i + 2] == '=' ? -2 : b64_value((uint8_t)text[i + 2]);
        int d = text[i + 3] == '=' ? -2 : b64_value((uint8_t)text[i + 3]);
        if (a < 0 || b < 0 || c == -1 || d == -1) return jpssl::nullopt;

        uint32_t v = (uint32_t)a << 18 | (uint32_t)b << 12;
        if (c >= 0) v |= (uint32_t)c << 6;
        if (d >= 0) v |= (uint32_t)d;

        out.push_back((uint8_t)(v >> 16));
        if (c >= 0) out.push_back((uint8_t)(v >> 8));
        if (d >= 0) out.push_back((uint8_t)v);

        // Padding, if present, must only occur in the final group.
        bool padded = text[i + 2] == '=' || text[i + 3] == '=';
        if (padded && i + 4 != n) return jpssl::nullopt;
        i += 4;
    }
    return out;
}

} // namespace jpssl
