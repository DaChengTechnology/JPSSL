#include "rsa_simd.hpp"
#include <cstring>
#include <cstdint>
#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace jpssl {

#ifdef __AVX2__

static inline __m256i cmpgt_epu64_avx2(__m256i a, __m256i b) {
    const __m256i sign = _mm256_set1_epi64x(0x8000000000000000ULL);
    return _mm256_cmpgt_epi64(_mm256_xor_si256(a, sign), _mm256_xor_si256(b, sign));
}

static inline void mont_mul_step1(const uint64_t* a_ptr, const uint64_t* b_ptr,
                                  uint64_t* t, uint64_t* carry, int K) {
    for (int j = 0; j < K; ++j) {
        __uint128_t p0 = (__uint128_t)a_ptr[0] * b_ptr[j] + t[j] + carry[0];
        __uint128_t p1 = (__uint128_t)a_ptr[1] * b_ptr[j] + t[j + K] + carry[1];
        __uint128_t p2 = (__uint128_t)a_ptr[2] * b_ptr[j] + t[j + 2*K] + carry[2];
        __uint128_t p3 = (__uint128_t)a_ptr[3] * b_ptr[j] + t[j + 3*K] + carry[3];
        t[j           ] = (uint64_t)p0; carry[0] = (uint64_t)(p0 >> 64);
        t[j + K       ] = (uint64_t)p1; carry[1] = (uint64_t)(p1 >> 64);
        t[j + 2*K     ] = (uint64_t)p2; carry[2] = (uint64_t)(p2 >> 64);
        t[j + 3*K     ] = (uint64_t)p3; carry[3] = (uint64_t)(p3 >> 64);
    }
}

static inline void mont_mul_step2(uint64_t u, const uint64_t* m,
                                  uint64_t* t, uint64_t* carry, int K, int msg_idx) {
    uint64_t* t_msg = t + msg_idx * (2*K + 1);
    for (int j = 0; j < K; ++j) {
        __uint128_t s = (__uint128_t)u * m[j] + t_msg[j] + *carry;
        t_msg[j] = (uint64_t)s;
        *carry = (uint64_t)(s >> 64);
    }
}

static inline void mont_mul_final_sub(uint64_t* r, const uint64_t* m,
                                       uint64_t* t, int K, int msg_idx) {
    uint64_t* t_msg = t + msg_idx * (2*K + 1);
    uint64_t* r_msg = r + msg_idx * K;
    for (int i = 0; i < K; ++i) r_msg[i] = t_msg[i + K];

    bool ge = false;
    for (int i = K - 1; i >= 0; --i) {
        if (r_msg[i] > m[i]) { ge = true; break; }
        if (r_msg[i] < m[i]) break;
    }
    if (ge) {
        uint64_t bo = 0;
        for (int i = 0; i < K; ++i) {
            uint64_t df = r_msg[i] - m[i] - bo;
            bo = (r_msg[i] < m[i] + bo) ? 1 : 0;
            r_msg[i] = df;
        }
    }
}

void batch_mont_mul_avx2(uint64_t* r, const uint64_t* a, const uint64_t* b,
                         const uint64_t* m, uint64_t mp, int K) {
    uint64_t t[4 * (2*64 + 1)] = {};
    int maxK = (K > 64) ? 64 : K;
    int t_len = 2 * maxK + 1;

    for (int i = 0; i < K; ++i) {
        uint64_t carry[4] = {0, 0, 0, 0};
        uint64_t a_lane[4], b_lane[4];
        for (int msg = 0; msg < 4; ++msg) {
            a_lane[msg] = a[msg * K + i];
        }

        for (int j = 0; j < K; ++j) {
            for (int msg = 0; msg < 4; ++msg) {
                b_lane[msg] = b[msg * K + j];
            }
            for (int msg = 0; msg < 4; ++msg) {
                uint64_t* t_msg = t + msg * t_len;
                __uint128_t p = (__uint128_t)a_lane[msg] * b_lane[msg]
                              + t_msg[i + j] + carry[msg];
                t_msg[i + j] = (uint64_t)p;
                carry[msg] = (uint64_t)(p >> 64);
            }
        }
        for (int msg = 0; msg < 4; ++msg) {
            t[msg * t_len + i + K] = carry[msg];
        }

        uint64_t u_vals[4];
        for (int msg = 0; msg < 4; ++msg) {
            u_vals[msg] = t[msg * t_len + i] * mp;
        }

        carry[0] = carry[1] = carry[2] = carry[3] = 0;
        for (int j = 0; j < K; ++j) {
            uint64_t mj = m[j];
            for (int msg = 0; msg < 4; ++msg) {
                uint64_t* t_msg = t + msg * t_len;
                __uint128_t s = (__uint128_t)u_vals[msg] * mj
                              + t_msg[i + j] + carry[msg];
                t_msg[i + j] = (uint64_t)s;
                carry[msg] = (uint64_t)(s >> 64);
            }
        }
        for (int msg = 0; msg < 4; ++msg) {
            uint64_t* t_msg = t + msg * t_len;
            int idx = i + K;
            while (carry[msg]) {
                __uint128_t s = (__uint128_t)t_msg[idx] + carry[msg];
                t_msg[idx] = (uint64_t)s;
                carry[msg] = (uint64_t)(s >> 64);
                ++idx;
            }
        }
    }

    for (int msg = 0; msg < 4; ++msg) {
        mont_mul_final_sub(r, m, t, K, msg);
    }
}

void batch_modpow_avx2(uint64_t* r, const uint64_t* bases,
                       const uint64_t* exp, const uint64_t* mod,
                       const uint64_t* R2, const uint64_t* R_mod_m,
                       uint64_t mp, int K, int exp_bits) {
    int t_len = 2 * K + 1;
    uint64_t bm[4 * K];
    uint64_t rm[4 * K];

    for (int msg = 0; msg < 4; ++msg) {
        uint64_t t_buf[2 * (2*64 + 1)] = {};
        uint64_t a_ptr = bases[msg * K + 0];
        (void)a_ptr;
    }

    uint64_t* t = new uint64_t[4 * (2 * K + 1)]();
    uint64_t carry[4];

    for (int msg = 0; msg < 4; ++msg) {
        const uint64_t* a_msg = bases + msg * K;
        uint64_t* rm_msg = rm + msg * K;
        for (int i = 0; i < K; ++i) rm_msg[i] = R_mod_m[i];
    }

    for (int msg = 0; msg < 4; ++msg) {
        memset(t + msg * t_len, 0, t_len * 8);
        carry[0] = carry[1] = carry[2] = carry[3] = 0;
        uint64_t a_lane = bases[msg * K + 0];
        (void)a_lane;
        for (int i = 0; i < K; ++i) {
            carry[0] = carry[1] = carry[2] = carry[3] = 0;
            uint64_t ai = bases[msg * K + i];
            for (int j = 0; j < K; ++j) {
                uint64_t* t_msg = t + msg * t_len;
                __uint128_t p = (__uint128_t)ai * R2[j] + t_msg[i + j] + carry[0];
                t_msg[i + j] = (uint64_t)p;
                carry[0] = (uint64_t)(p >> 64);
            }
            t[msg * t_len + i + K] = carry[0];

            uint64_t u = t[msg * t_len + i] * mp;
            carry[0] = 0;
            for (int j = 0; j < K; ++j) {
                uint64_t* t_msg = t + msg * t_len;
                __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry[0];
                t_msg[i + j] = (uint64_t)s;
                carry[0] = (uint64_t)(s >> 64);
            }
            int idx = i + K;
            uint64_t* t_msg = t + msg * t_len;
            while (carry[0]) {
                __uint128_t s = (__uint128_t)t_msg[idx] + carry[0];
                t_msg[idx] = (uint64_t)s;
                carry[0] = (uint64_t)(s >> 64);
                ++idx;
            }
        }
        uint64_t* bm_msg = bm + msg * K;
        for (int i = 0; i < K; ++i) bm_msg[i] = t[msg * t_len + i + K];
        bool ge = false;
        for (int i = K - 1; i >= 0; --i) {
            if (bm_msg[i] > mod[i]) { ge = true; break; }
            if (bm_msg[i] < mod[i]) break;
        }
        if (ge) {
            uint64_t bo = 0;
            for (int i = 0; i < K; ++i) {
                uint64_t df = bm_msg[i] - mod[i] - bo;
                bo = (bm_msg[i] < mod[i] + bo) ? 1 : 0;
                bm_msg[i] = df;
            }
        }
    }

    for (int bit = exp_bits - 1; bit >= 0; --bit) {
        int w = bit / 64;
        int b = bit % 64;
        int e_bit = (exp[w] >> b) & 1;

        memset(t, 0, 4 * t_len * 8);
        for (int msg = 0; msg < 4; ++msg) {
            carry[msg] = 0;
            uint64_t* rm_msg = rm + msg * K;
            uint64_t* t_msg = t + msg * t_len;
            for (int i = 0; i < K; ++i) {
                carry[msg] = 0;
                for (int j = 0; j < K; ++j) {
                    __uint128_t p = (__uint128_t)rm_msg[i] * rm_msg[j]
                                  + t_msg[i + j] + carry[msg];
                    t_msg[i + j] = (uint64_t)p;
                    carry[msg] = (uint64_t)(p >> 64);
                }
                t_msg[i + K] = carry[msg];

                uint64_t u = t_msg[i] * mp;
                carry[msg] = 0;
                for (int j = 0; j < K; ++j) {
                    __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry[msg];
                    t_msg[i + j] = (uint64_t)s;
                    carry[msg] = (uint64_t)(s >> 64);
                }
                int idx = i + K;
                while (carry[msg]) {
                    __uint128_t s = (__uint128_t)t_msg[idx] + carry[msg];
                    t_msg[idx] = (uint64_t)s;
                    carry[msg] = (uint64_t)(s >> 64);
                    ++idx;
                }
            }
            for (int i = 0; i < K; ++i) rm_msg[i] = t_msg[i + K];
            bool ge = false;
            for (int i = K - 1; i >= 0; --i) {
                if (rm_msg[i] > mod[i]) { ge = true; break; }
                if (rm_msg[i] < mod[i]) break;
            }
            if (ge) {
                uint64_t bo = 0;
                for (int i = 0; i < K; ++i) {
                    uint64_t df = rm_msg[i] - mod[i] - bo;
                    bo = (rm_msg[i] < mod[i] + bo) ? 1 : 0;
                    rm_msg[i] = df;
                }
            }
        }

        if (e_bit) {
            memset(t, 0, 4 * t_len * 8);
            for (int msg = 0; msg < 4; ++msg) {
                carry[msg] = 0;
                uint64_t* rm_msg = rm + msg * K;
                uint64_t* bm_msg = bm + msg * K;
                uint64_t* t_msg = t + msg * t_len;
                for (int i = 0; i < K; ++i) {
                    carry[msg] = 0;
                    for (int j = 0; j < K; ++j) {
                        __uint128_t p = (__uint128_t)rm_msg[i] * bm_msg[j]
                                      + t_msg[i + j] + carry[msg];
                        t_msg[i + j] = (uint64_t)p;
                        carry[msg] = (uint64_t)(p >> 64);
                    }
                    t_msg[i + K] = carry[msg];

                    uint64_t u = t_msg[i] * mp;
                    carry[msg] = 0;
                    for (int j = 0; j < K; ++j) {
                        __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry[msg];
                        t_msg[i + j] = (uint64_t)s;
                        carry[msg] = (uint64_t)(s >> 64);
                    }
                    int idx = i + K;
                    while (carry[msg]) {
                        __uint128_t s = (__uint128_t)t_msg[idx] + carry[msg];
                        t_msg[idx] = (uint64_t)s;
                        carry[msg] = (uint64_t)(s >> 64);
                        ++idx;
                    }
                }
                for (int i = 0; i < K; ++i) rm_msg[i] = t_msg[i + K];
                bool ge = false;
                for (int i = K - 1; i >= 0; --i) {
                    if (rm_msg[i] > mod[i]) { ge = true; break; }
                    if (rm_msg[i] < mod[i]) break;
                }
                if (ge) {
                    uint64_t bo = 0;
                    for (int i = 0; i < K; ++i) {
                        uint64_t df = rm_msg[i] - mod[i] - bo;
                        bo = (rm_msg[i] < mod[i] + bo) ? 1 : 0;
                        rm_msg[i] = df;
                    }
                }
            }
        }
    }

    for (int msg = 0; msg < 4; ++msg) {
        uint64_t one[64] = {};
        one[0] = 1;
        memset(t, 0, t_len * 8);
        uint64_t* rm_msg = rm + msg * K;
        uint64_t* t_msg = t;
        carry[0] = 0;
        for (int i = 0; i < K; ++i) {
            carry[0] = 0;
            for (int j = 0; j < K; ++j) {
                __uint128_t p = (__uint128_t)rm_msg[i] * one[j]
                              + t_msg[i + j] + carry[0];
                t_msg[i + j] = (uint64_t)p;
                carry[0] = (uint64_t)(p >> 64);
            }
            t_msg[i + K] = carry[0];

            uint64_t u = t_msg[i] * mp;
            carry[0] = 0;
            for (int j = 0; j < K; ++j) {
                __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry[0];
                t_msg[i + j] = (uint64_t)s;
                carry[0] = (uint64_t)(s >> 64);
            }
            int idx = i + K;
            while (carry[0]) {
                __uint128_t s = (__uint128_t)t_msg[idx] + carry[0];
                t_msg[idx] = (uint64_t)s;
                carry[0] = (uint64_t)(s >> 64);
                ++idx;
            }
        }
        uint64_t* r_msg = r + msg * K;
        for (int i = 0; i < K; ++i) r_msg[i] = t_msg[i + K];
        bool ge = false;
        for (int i = K - 1; i >= 0; --i) {
            if (r_msg[i] > mod[i]) { ge = true; break; }
            if (r_msg[i] < mod[i]) break;
        }
        if (ge) {
            uint64_t bo = 0;
            for (int i = 0; i < K; ++i) {
                uint64_t df = r_msg[i] - mod[i] - bo;
                bo = (r_msg[i] < mod[i] + bo) ? 1 : 0;
                r_msg[i] = df;
            }
        }
    }

    delete[] t;
}

#else
void batch_mont_mul_avx2(uint64_t*, const uint64_t*, const uint64_t*,
                         const uint64_t*, uint64_t, int) {}
void batch_modpow_avx2(uint64_t*, const uint64_t*, const uint64_t*,
                       const uint64_t*, const uint64_t*, const uint64_t*,
                       uint64_t, int, int) {}
#endif

} // namespace jpssl
