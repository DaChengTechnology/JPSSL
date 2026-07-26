#include "sha256.hpp"
#include <cstring>
#ifdef __x86_64__
#include <immintrin.h>

namespace jpssl {
namespace {

static void sha256_transform_sha_ni(uint32_t h[8], const uint8_t data[64]) {
    __m128i STATE0, STATE1, MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    static const __m128i MASK = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

    TMP = _mm_loadu_si128((const __m128i*) &h[0]);
    STATE1 = _mm_loadu_si128((const __m128i*) &h[4]);

    TMP = _mm_shuffle_epi32(TMP, 0xB1);
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);

    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data)), MASK);
    MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 16)), MASK);
    MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 32)), MASK);
    MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 48)), MASK);

    // Rounds 0-3
    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0xe9b5dba5, 0xb5c0fbcf, 0x71374491, 0x428a2f98));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 4-7
    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0xab1c5ed5, 0x923f82a4, 0x59f111f1, 0x3956c25b));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 8-11
    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0x550c7dc3, 0x243185be, 0x12835b01, 0xd807aa98));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 12-15
    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0xc19bf174, 0x9bdc06a7, 0x80deb1fe, 0x72be5d74));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 16-19
    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0x240ca1cc, 0x0fc19dc6, 0xefbe4786, 0xe49b69c1));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 20-23
    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0x76f988da, 0x5cb0a9dc, 0x4a7484aa, 0x2de92c6f));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 24-27
    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0xbf597fc7, 0xb00327c8, 0xa831c66d, 0x983e5152));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 28-31
    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0x14292967, 0x06ca6351, 0xd5a79147, 0xc6e00bf3));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 32-35
    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0x53380d13, 0x4d2c6dfc, 0x2e1b2138, 0x27b70a85));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 36-39
    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0x92722c85, 0x81c2c92e, 0x766a0abb, 0x650a7354));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 40-43
    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0xc76c51a3, 0xc24b8b70, 0xa81a664b, 0xa2bfe8a1));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 44-47
    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0x106aa070, 0xf40e3585, 0xd6990624, 0xd192e819));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0 = _mm_add_epi32(MSG0, TMP);
    MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 48-51
    MSG = _mm_add_epi32(MSG0, _mm_set_epi32(0x34b0bcb5, 0x2748774c, 0x1e376c08, 0x19a4c116));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1 = _mm_add_epi32(MSG1, TMP);
    MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 52-55
    MSG = _mm_add_epi32(MSG1, _mm_set_epi32(0x682e6ff3, 0x5b9cca4f, 0x4ed8aa4a, 0x391c0cb3));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2 = _mm_add_epi32(MSG2, TMP);
    MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 56-59
    MSG = _mm_add_epi32(MSG2, _mm_set_epi32(0x8cc70208, 0x84c87814, 0x78a5636f, 0x748f82ee));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3 = _mm_add_epi32(MSG3, TMP);
    MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 60-63
    MSG = _mm_add_epi32(MSG3, _mm_set_epi32(0xc67178f2, 0xbef9a3f7, 0xa4506ceb, 0x90befffa));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);

    _mm_storeu_si128((__m128i*) &h[0], STATE0);
    _mm_storeu_si128((__m128i*) &h[4], STATE1);
}

} // anonymous namespace

void sha256_sha_ni(uint8_t digest[32], const uint8_t* data, size_t len) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t bits = 0;
    uint8_t buf[128];
    size_t buf_len = 0;

    bits += len * 8;
    while (len > 0) {
        size_t space = 64 - buf_len;
        size_t take = (len < space) ? len : space;
        std::memcpy(buf + buf_len, data, take);
        buf_len += take;
        data += take;
        len -= take;
        if (buf_len == 64) {
            sha256_transform_sha_ni(h, buf);
            buf_len = 0;
        }
    }

    buf[buf_len++] = 0x80;
    if (buf_len > 56) {
        while (buf_len < 64) buf[buf_len++] = 0;
        sha256_transform_sha_ni(h, buf);
        buf_len = 0;
    }
    while (buf_len < 56) buf[buf_len++] = 0;
    for (int i = 7; i >= 0; --i)
        buf[buf_len++] = (uint8_t)(bits >> (i * 8));
    sha256_transform_sha_ni(h, buf);

    for (int i = 0; i < 32; ++i)
        digest[i] = ((uint8_t*)h)[i ^ 3];
}

} // namespace jpssl
#endif // __x86_64__
