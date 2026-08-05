/**
 * base64_avx2.cpp -- RFC 4648 base64, AVX2 accelerated encode/decode.
 *
 * Encode: 24 input bytes -> 32 output bytes per iteration.  Two 128-bit
 * loads feed a 256-bit shuffle that places each 3-byte triplet into its own
 * 32-bit lane; four 6-bit indices per lane are extracted with 16-bit
 * multiply-high / multiply-low, then mapped to ASCII via a pshufb table.
 *
 * Decode: 32 input chars -> 24 output bytes per iteration.  Characters are
 * validated and converted to 6-bit values with a pshufb table keyed on the
 * high nibble, then packed 4x6 -> 3 bytes with maddubs/madd.
 *
 * This follows the classic Wojciech MuÅ‚a base64-SIMD technique.
 * Compile with -mavx2 (GCC/Clang) or /arch:AVX2 (MSVC).
 */
#include "base64_internal.hpp"

#include <immintrin.h>
#include <cstring>
#include <cstdint>

namespace jpssl {
namespace detail {
namespace {

/// [hi : lo] as a 256-bit vector (lo in the low 128-bit lane).
inline __m256i concat128(__m128i hi, __m128i lo) {
    return _mm256_insertf128_si256(_mm256_castsi128_si256(lo), hi, 1);
}

/// Encoding character table: for a 6-bit index i, returns i + shift(i).
/// shift is looked up after saturating (i - 51), or forced to 13 for i < 26.
inline __m256i encode_shift_lut() {
    return _mm256_setr_epi8(
        'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
        '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62,
        '/' - 63, 'A', 0, 0,
        'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
        '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62,
        '/' - 63, 'A', 0, 0);
}

/// Map 3 input bytes (one per 32-bit lane) to four 6-bit indices per lane.
inline __m256i encode_indices(__m256i in) {
    const __m256i t0 = _mm256_and_si256(in, _mm256_set1_epi32(0x0fc0fc00));
    const __m256i t1 = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x04000040));
    const __m256i t2 = _mm256_and_si256(in, _mm256_set1_epi32(0x003f03f0));
    const __m256i t3 = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x01000010));
    return _mm256_or_si256(t1, t3);
}

/// Map 6-bit indices to base64 characters.
inline __m256i encode_chars(__m256i idx) {
    __m256i t = _mm256_subs_epu8(idx, _mm256_set1_epi8(51));
    const __m256i less = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), idx);
    t = _mm256_or_si256(t, _mm256_and_si256(less, _mm256_set1_epi8(13)));
    const __m256i shift = _mm256_shuffle_epi8(encode_shift_lut(), t);
    return _mm256_add_epi8(idx, shift);
}

/// Decode lookup tables keyed on the high nibble of the input character.
inline __m256i decode_lower_lut() {
    return _mm256_setr_epi8(
        1, 1, 0x2b, 0x30, 0x41, 0x50, 0x61, 0x70,
        1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 0x2b, 0x30, 0x41, 0x50, 0x61, 0x70,
        1, 1, 1, 1, 1, 1, 1, 1);
}

inline __m256i decode_upper_lut() {
    return _mm256_setr_epi8(
        0, 0, 0x2b, 0x39, 0x4f, 0x5a, 0x6f, 0x7a,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0x2b, 0x39, 0x4f, 0x5a, 0x6f, 0x7a,
        0, 0, 0, 0, 0, 0, 0, 0);
}

inline __m256i decode_shift_lut() {
    return _mm256_setr_epi8(
        0, 0, 19, 4, -65, -65, -71, -71,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 19, 4, -65, -65, -71, -71,
        0, 0, 0, 0, 0, 0, 0, 0);
}

/// Validate base64 characters and convert them to 6-bit values.
/// Returns false on the first invalid character.
inline bool decode_values(__m256i in, __m256i& values) {
    const __m256i higher = _mm256_and_si256(_mm256_srli_epi32(in, 4),
                                            _mm256_set1_epi8(0x0f));
    const __m256i lower_bound = _mm256_shuffle_epi8(decode_lower_lut(), higher);
    const __m256i upper_bound = _mm256_shuffle_epi8(decode_upper_lut(), higher);
    const __m256i below = _mm256_cmpgt_epi8(lower_bound, in);
    const __m256i above = _mm256_cmpgt_epi8(in, upper_bound);
    const __m256i eq_2f = _mm256_cmpeq_epi8(in, _mm256_set1_epi8(0x2f));
    const __m256i outside = _mm256_andnot_si256(eq_2f, _mm256_or_si256(below, above));
    if (_mm256_movemask_epi8(outside) != 0) return false;

    const __m256i shift = _mm256_shuffle_epi8(decode_shift_lut(), higher);
    const __m256i t0 = _mm256_add_epi8(in, shift);
    values = _mm256_add_epi8(t0, _mm256_and_si256(eq_2f, _mm256_set1_epi8(-3)));
    return true;
}

/// Pack four 6-bit values per 32-bit lane into three output bytes per lane.
inline __m256i pack_values(__m256i values) {
    const __m256i t0 = _mm256_maddubs_epi16(values, _mm256_set1_epi32(0x01400140));
    return _mm256_madd_epi16(t0, _mm256_set1_epi32(0x00011000));
}

} // namespace

size_t base64_encode_avx2(const uint8_t* data, size_t len, char* out) {
    // After the shuffle each 128-bit lane holds 4 triplets spread over 16
    // bytes; byte order (lowest dword first) is 1,0,2,1 per dword so the
    // three bytes of a triplet end up in three consecutive dword positions.
    static const __m256i shuf = _mm256_set_epi8(
        10, 11, 9, 10,
         7,  8, 6,  7,
         4,  5, 3,  4,
         1,  2, 0,  1,

        10, 11, 9, 10,
         7,  8, 6,  7,
         4,  5, 3,  4,
         1,  2, 0,  1);

    size_t i = 0;
    for (; i + 28 <= len; i += 24) {
        // 24 input bytes: 12 in the low lane (A..D), 12 in the high lane (E..H).
        const __m128i lo = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i));
        const __m128i hi = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i + 12));
        const __m256i in = _mm256_shuffle_epi8(concat128(hi, lo), shuf);
        const __m256i chars = encode_chars(encode_indices(in));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + (i / 3) * 4), chars);
    }
    return i;
}

bool base64_decode_avx2(const char* text, size_t len, uint8_t* out) {
    static const __m256i shuf = _mm256_setr_epi8(
         2,  1,  0,
         6,  5,  4,
        10,  9,  8,
        14, 13, 12,
        -1, -1, -1, -1,

         2,  1,  0,
         6,  5,  4,
        10,  9,  8,
        14, 13, 12,
        -1, -1, -1, -1);

    for (size_t i = 0; i < len; i += 32) {
        const __m256i in = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(text + i));
        __m256i values;
        if (!decode_values(in, values)) return false;

        const __m256i packed = pack_values(values);
        const __m256i shuffled = _mm256_shuffle_epi8(packed, shuf);

        uint8_t* dst = out + (i / 4) * 3;
        const __m128i lane0 = _mm256_extracti128_si256(shuffled, 0);
        const __m128i lane1 = _mm256_extracti128_si256(shuffled, 1);
        // lane0's low 12 bytes and lane1's low 12 bytes are the 24 output
        // bytes.  Store exactly 12 bytes from lane1 (a 16-byte store would
        // overrun the output buffer by 4 bytes).
        _mm_storeu_si128(reinterpret_cast<__m128i*>(dst), lane0);
        _mm_storel_epi64(reinterpret_cast<__m128i*>(dst + 12), lane1);
        const uint32_t tail = static_cast<uint32_t>(_mm_extract_epi32(lane1, 2));
        std::memcpy(dst + 20, &tail, sizeof(tail));
    }
    return true;
}

} // namespace detail
} // namespace jpssl
