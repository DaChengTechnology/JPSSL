/**
 * base64_avx512.cpp -- RFC 4648 base64, AVX-512 accelerated encode/decode.
 *
 * Encode: 48 input bytes -> 64 output bytes per iteration.  The 48 bytes are
 * assembled from two 256-bit loads, each 12-byte triplet is isolated in its
 * own 32-bit lane, four 6-bit indices per lane are extracted with 16-bit
 * multiply-high / multiply-low (AVX512BW), then mapped to ASCII via a pshufb
 * table.
 *
 * Decode: 64 input chars -> 48 output bytes per iteration.  Characters are
 * validated and converted to 6-bit values with a pshufb table keyed on the
 * high nibble, packed 4x6 -> 3 bytes with maddubs/madd, reordered and stored
 * with a masked store (only the 48 meaningful bytes are written).
 *
 * Same technique as base64_avx2.cpp (Wojciech MuÅ‚a base64-SIMD), widened to
 * 512-bit registers.  Compile with -mavx512f -mavx512bw (GCC/Clang) or
 * /arch:AVX512 (MSVC).
 */
#include "base64_internal.hpp"

#include <immintrin.h>
#include <cstdint>

namespace jpssl {
namespace detail {
namespace {

/// Broadcast a 16-byte table to all four 128-bit lanes of a 512-bit vector.
inline __m512i bcast128(__m128i v) {
    return _mm512_broadcast_i32x4(v);
}

inline __m512i encode_shift_lut() {
    return bcast128(_mm_setr_epi8(
        'a' - 26, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
        '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62,
        '/' - 63, 'A', 0, 0));
}

/// Map 3 input bytes (one per 32-bit lane) to four 6-bit indices per lane.
inline __m512i encode_indices(__m512i in) {
    const __m512i t0 = _mm512_and_si512(in, _mm512_set1_epi32(0x0fc0fc00));
    const __m512i t1 = _mm512_mulhi_epu16(t0, _mm512_set1_epi32(0x04000040));
    const __m512i t2 = _mm512_and_si512(in, _mm512_set1_epi32(0x003f03f0));
    const __m512i t3 = _mm512_mullo_epi16(t2, _mm512_set1_epi32(0x01000010));
    return _mm512_or_si512(t1, t3);
}

/// Map 6-bit indices to base64 characters.
inline __m512i encode_chars(__m512i idx) {
    __m512i t = _mm512_subs_epu8(idx, _mm512_set1_epi8(51));
    const __mmask64 less = _mm512_cmpgt_epi8_mask(_mm512_set1_epi8(26), idx);
    t = _mm512_or_si512(t, _mm512_maskz_set1_epi8(less, 13));
    const __m512i shift = _mm512_shuffle_epi8(encode_shift_lut(), t);
    return _mm512_add_epi8(idx, shift);
}

/// Decode lookup tables keyed on the high nibble of the input character.
inline __m512i decode_lower_lut() {
    return bcast128(_mm_setr_epi8(
        1, 1, 0x2b, 0x30, 0x41, 0x50, 0x61, 0x70,
        1, 1, 1, 1, 1, 1, 1, 1));
}

inline __m512i decode_upper_lut() {
    return bcast128(_mm_setr_epi8(
        0, 0, 0x2b, 0x39, 0x4f, 0x5a, 0x6f, 0x7a,
        0, 0, 0, 0, 0, 0, 0, 0));
}

inline __m512i decode_shift_lut() {
    return bcast128(_mm_setr_epi8(
        0, 0, 19, 4, -65, -65, -71, -71,
        0, 0, 0, 0, 0, 0, 0, 0));
}

/// Validate base64 characters and convert them to 6-bit values.
/// Returns false if any character is invalid.
inline bool decode_values(__m512i in, __m512i& values) {
    const __m512i higher = _mm512_and_si512(_mm512_srli_epi32(in, 4),
                                            _mm512_set1_epi8(0x0f));
    const __m512i lower_bound = _mm512_shuffle_epi8(decode_lower_lut(), higher);
    const __m512i upper_bound = _mm512_shuffle_epi8(decode_upper_lut(), higher);
    const __mmask64 below = _mm512_cmpgt_epi8_mask(lower_bound, in);
    const __mmask64 above = _mm512_cmpgt_epi8_mask(in, upper_bound);
    const __mmask64 eq_2f = _mm512_cmpeq_epi8_mask(in, _mm512_set1_epi8(0x2f));
    if (((below | above) & ~eq_2f) != 0) return false;

    const __m512i shift = _mm512_shuffle_epi8(decode_shift_lut(), higher);
    const __m512i t0 = _mm512_add_epi8(in, shift);
    values = _mm512_add_epi8(t0, _mm512_maskz_set1_epi8(eq_2f, -3));
    return true;
}

/// Pack four 6-bit values per 32-bit lane into three output bytes per lane.
inline __m512i pack_values(__m512i values) {
    const __m512i t0 = _mm512_maddubs_epi16(values, _mm512_set1_epi32(0x01400140));
    return _mm512_madd_epi16(t0, _mm512_set1_epi32(0x00011000));
}

} // namespace

size_t base64_encode_avx512(const uint8_t* data, size_t len, char* out) {
    // 输入按两个 32 字节加载拼成 512 位：dword[0..7] = 字节 [0..32)，
    // dword[8..15] = 字节 [16..48)（低半部分与 dword[4..7] 重叠）。
    // perm 把每个 12 字节子块（4 组 × 3 字节）的 3 个 dword 排进各自的
    // 128 位 lane（第 4 个 dword 为占位，VPSHUFB 不会读取它）。
    // 随后 VPSHUFB 在 lane 内构造与 base64_avx2 完全一致的逐 dword 布局
    // [b1, b0, b2, b1]（字节 0/1/2/3 = 输入第 1/0/2/1 字节），
    // 再走同一套 encode_indices / encode_chars。
    // 注意：不能照抄 OpenSSL/WojciechMuła 单次 64 字节加载版本的
    // perm+shift+merge（其 dword[8..15] = 字节 [32..64)，与此处布局不同）。
    static const __m512i perm = _mm512_set_epi32(
        0, 15, 14, 13, 0, 12, 7, 6,
        0,  5,  4,  3, 0,  2, 1, 0);

    static const __m512i shuf = _mm512_setr_epi8(
         1,  0,  2,  1,
         4,  3,  5,  4,
         7,  6,  8,  7,
        10,  9, 11, 10,

         1,  0,  2,  1,
         4,  3,  5,  4,
         7,  6,  8,  7,
        10,  9, 11, 10,

         1,  0,  2,  1,
         4,  3,  5,  4,
         7,  6,  8,  7,
        10,  9, 11, 10,

         1,  0,  2,  1,
         4,  3,  5,  4,
         7,  6,  8,  7,
        10,  9, 11, 10);

    size_t i = 0;
    for (; i + 48 <= len; i += 48) {
        const __m256i lo = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
        const __m256i hi = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i + 16));
        __m512i tmp = _mm512_inserti64x4(_mm512_castsi256_si512(lo), hi, 1);
        tmp = _mm512_permutexvar_epi32(perm, tmp);
        const __m512i tri = _mm512_shuffle_epi8(tmp, shuf);
        const __m512i chars = encode_chars(encode_indices(tri));
        _mm512_storeu_si512(reinterpret_cast<void*>(out + (i / 3) * 4), chars);
    }
    return i;
}

bool base64_decode_avx512(const char* text, size_t len, uint8_t* out) {
    // Per 128-bit lane: pick bytes 2,1,0 / 6,5,4 / 10,9,8 / 14,13,12.
    static const __m512i shuf = bcast128(_mm_setr_epi8(
         2,  1,  0,
         6,  5,  4,
        10,  9,  8,
        14, 13, 12,
        -1, -1, -1, -1));

    // Gather the 12 meaningful dwords (3 per lane) into the low 48 bytes.
    static const __m512i gather = _mm512_setr_epi32(
         0,  1,  2,
         4,  5,  6,
         8,  9, 10,
        12, 13, 14,
         0,  0,  0, 0);

    for (size_t i = 0; i < len; i += 64) {
        const __m512i in = _mm512_loadu_si512(reinterpret_cast<const void*>(text + i));
        __m512i values;
        if (!decode_values(in, values)) return false;

        const __m512i packed = pack_values(values);
        const __m512i t1 = _mm512_shuffle_epi8(packed, shuf);
        const __m512i t2 = _mm512_permutexvar_epi32(gather, t1);

        _mm512_mask_storeu_epi32(reinterpret_cast<void*>(out + (i / 4) * 3),
                                 0x0fff, t2);
    }
    return true;
}

} // namespace detail
} // namespace jpssl
