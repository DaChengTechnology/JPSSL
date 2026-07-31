#include "rsa_simd.hpp"
#include <cstring>
#include <cstdint>
#ifdef __AVX512F__
#include <immintrin.h>
#endif

namespace jpssl {

#ifdef __AVX512F__

void batch_mont_mul_avx512(uint64_t* r, const uint64_t* a, const uint64_t* b,
                           const uint64_t* m, uint64_t mp, int K) {
    int t_len = 2 * K + 2;
    uint64_t* t = new uint64_t[8 * t_len]();
    uint64_t carry[8];

    for (int i = 0; i < K; ++i) {
        for (int msg = 0; msg < 8; ++msg) carry[msg] = 0;

        uint64_t a_lane[8];
        for (int msg = 0; msg < 8; ++msg)
            a_lane[msg] = a[msg * K + i];

        for (int j = 0; j < K; ++j) {
            uint64_t b_vals[8];
            for (int msg = 0; msg < 8; ++msg) b_vals[msg] = b[msg * K + j];
            for (int msg = 0; msg < 8; ++msg) {
                uint64_t* t_msg = t + msg * t_len;
                __uint128_t p = (__uint128_t)a_lane[msg] * b_vals[msg]
                              + t_msg[i + j] + carry[msg];
                t_msg[i + j] = (uint64_t)p;
                carry[msg] = (uint64_t)(p >> 64);
            }
        }
        for (int msg = 0; msg < 8; ++msg) {
            uint64_t* t_msg = t + msg * t_len;
            uint64_t sc = t_msg[i + K] + carry[msg];
            t_msg[i + K] = sc;
            if (sc < carry[msg]) {
                int idx = i + K + 1;
                while (true) {
                    uint64_t s2 = t_msg[idx] + 1;
                    t_msg[idx] = s2;
                    if (s2) break;
                    ++idx;
                }
            }
        }

        uint64_t u_vals[8];
        for (int msg = 0; msg < 8; ++msg)
            u_vals[msg] = t[msg * t_len + i] * mp;

        for (int msg = 0; msg < 8; ++msg) carry[msg] = 0;
        for (int j = 0; j < K; ++j) {
            uint64_t mj = m[j];
            for (int msg = 0; msg < 8; ++msg) {
                uint64_t* t_msg = t + msg * t_len;
                __uint128_t s = (__uint128_t)u_vals[msg] * mj
                              + t_msg[i + j] + carry[msg];
                t_msg[i + j] = (uint64_t)s;
                carry[msg] = (uint64_t)(s >> 64);
            }
        }
        for (int msg = 0; msg < 8; ++msg) {
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

    for (int msg = 0; msg < 8; ++msg) {
        uint64_t* r_msg = r + msg * K;
        uint64_t* t_msg = t + msg * t_len;
        for (int i = 0; i < K; ++i) r_msg[i] = t_msg[i + K];

        if (t_msg[2*K]) {
            uint64_t bo = 0;
            for (int i = 0; i < K; ++i) {
                uint64_t df = r_msg[i] - m[i] - bo;
                bo = (r_msg[i] < m[i] + bo) ? 1 : 0;
                r_msg[i] = df;
            }
        }

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

    delete[] t;
}

void batch_modpow_avx512(uint64_t* r, const uint64_t* bases,
                         const uint64_t* exp, const uint64_t* mod,
                         const uint64_t* R2, const uint64_t* R_mod_m,
                         uint64_t mp, int K, int exp_bits) {
    int t_len = 2 * K + 2;
    uint64_t* bm = new uint64_t[8 * K];
    uint64_t* rm = new uint64_t[8 * K];
    uint64_t* t = new uint64_t[8 * t_len]();
    uint64_t carry[8];

    for (int msg = 0; msg < 8; ++msg) {
        uint64_t* rm_msg = rm + msg * K;
        for (int i = 0; i < K; ++i) rm_msg[i] = R_mod_m[i];
    }

    // To Montgomery: bm = mont_mul(base, R2)
    for (int msg = 0; msg < 8; ++msg) {
        memset(t + msg * t_len, 0, t_len * 8);
        carry[0] = 0;
        for (int i = 0; i < K; ++i) {
            uint64_t* t_msg = t + msg * t_len;
            carry[0] = 0;
            uint64_t ai = bases[msg * K + i];
            for (int j = 0; j < K; ++j) {
                __uint128_t p = (__uint128_t)ai * R2[j] + t_msg[i + j] + carry[0];
                t_msg[i + j] = (uint64_t)p;
                carry[0] = (uint64_t)(p >> 64);
            }
            uint64_t sc = t_msg[i + K] + carry[0];
            t_msg[i + K] = sc;
            if (sc < carry[0]) {
                int idx = i + K + 1;
                while (true) {
                    uint64_t s2 = t_msg[idx] + 1;
                    t_msg[idx] = s2;
                    if (s2) break;
                    ++idx;
                }
            }

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
        uint64_t* bm_msg = bm + msg * K;
        for (int i = 0; i < K; ++i) bm_msg[i] = t[msg * t_len + i + K];

        if (t[msg * t_len + 2*K]) {
            uint64_t bo = 0;
            for (int i = 0; i < K; ++i) {
                uint64_t df = bm_msg[i] - mod[i] - bo;
                bo = (bm_msg[i] < mod[i] + bo) ? 1 : 0;
                bm_msg[i] = df;
            }
        }
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

        memset(t, 0, 8 * t_len * 8);
        for (int msg = 0; msg < 8; ++msg) {
            uint64_t* rm_msg = rm + msg * K;
            uint64_t* t_msg = t + msg * t_len;
            carry[0] = 0;
            for (int i = 0; i < K; ++i) {
                const uint64_t ai = rm_msg[i];
                carry[0] = 0;
                for (int j = 0; j < K; ++j) {
                    __uint128_t p = (__uint128_t)ai * rm_msg[j]
                                  + t_msg[i + j] + carry[0];
                    t_msg[i + j] = (uint64_t)p;
                    carry[0] = (uint64_t)(p >> 64);
                }
                uint64_t sc = t_msg[i + K] + carry[0];
                t_msg[i + K] = sc;
                if (sc < carry[0]) {
                    int idx = i + K + 1;
                    while (true) {
                        uint64_t s2 = t_msg[idx] + 1;
                        t_msg[idx] = s2;
                        if (s2) break;
                        ++idx;
                    }
                }

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
            for (int i = 0; i < K; ++i) rm_msg[i] = t_msg[i + K];

            if (t_msg[2*K]) {
                uint64_t bo = 0;
                for (int i = 0; i < K; ++i) {
                    uint64_t df = rm_msg[i] - mod[i] - bo;
                    bo = (rm_msg[i] < mod[i] + bo) ? 1 : 0;
                    rm_msg[i] = df;
                }
            }
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
            memset(t, 0, 8 * t_len * 8);
            for (int msg = 0; msg < 8; ++msg) {
                uint64_t* rm_msg = rm + msg * K;
                uint64_t* bm_msg = bm + msg * K;
                uint64_t* t_msg = t + msg * t_len;
                carry[0] = 0;
                for (int i = 0; i < K; ++i) {
                    const uint64_t ai = rm_msg[i];
                    carry[0] = 0;
                    for (int j = 0; j < K; ++j) {
                        __uint128_t p = (__uint128_t)ai * bm_msg[j]
                                      + t_msg[i + j] + carry[0];
                        t_msg[i + j] = (uint64_t)p;
                        carry[0] = (uint64_t)(p >> 64);
                    }
                    uint64_t sc = t_msg[i + K] + carry[0];
                    t_msg[i + K] = sc;
                    if (sc < carry[0]) {
                        int idx = i + K + 1;
                        while (true) {
                            uint64_t s2 = t_msg[idx] + 1;
                            t_msg[idx] = s2;
                            if (s2) break;
                            ++idx;
                        }
                    }

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
                for (int i = 0; i < K; ++i) rm_msg[i] = t_msg[i + K];

                if (t_msg[2*K]) {
                    uint64_t bo = 0;
                    for (int i = 0; i < K; ++i) {
                        uint64_t df = rm_msg[i] - mod[i] - bo;
                        bo = (rm_msg[i] < mod[i] + bo) ? 1 : 0;
                        rm_msg[i] = df;
                    }
                }
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

    // From Montgomery: r = mont_mul(rm, 1)
    for (int msg = 0; msg < 8; ++msg) {
        uint64_t one[64] = {};
        one[0] = 1;
        memset(t + msg * t_len, 0, t_len * 8);
        uint64_t* rm_msg = rm + msg * K;
        uint64_t* t_msg = t + msg * t_len;
        carry[0] = 0;
        for (int i = 0; i < K; ++i) {
            carry[0] = 0;
            for (int j = 0; j < K; ++j) {
                __uint128_t p = (__uint128_t)rm_msg[i] * one[j]
                              + t_msg[i + j] + carry[0];
                t_msg[i + j] = (uint64_t)p;
                carry[0] = (uint64_t)(p >> 64);
            }
            uint64_t sc = t_msg[i + K] + carry[0];
            t_msg[i + K] = sc;
            if (sc < carry[0]) {
                int idx = i + K + 1;
                while (true) {
                    uint64_t s2 = t_msg[idx] + 1;
                    t_msg[idx] = s2;
                    if (s2) break;
                    ++idx;
                }
            }
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

        if (t_msg[2*K]) {
            uint64_t bo = 0;
            for (int i = 0; i < K; ++i) {
                uint64_t df = r_msg[i] - mod[i] - bo;
                bo = (r_msg[i] < mod[i] + bo) ? 1 : 0;
                r_msg[i] = df;
            }
        }
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
    delete[] bm;
    delete[] rm;
}

#else
void batch_mont_mul_avx512(uint64_t*, const uint64_t*, const uint64_t*,
                           const uint64_t*, uint64_t, int) {}
void batch_modpow_avx512(uint64_t*, const uint64_t*, const uint64_t*,
                         const uint64_t*, const uint64_t*, const uint64_t*,
                         uint64_t, int, int) {}
#endif

} // namespace jpssl
