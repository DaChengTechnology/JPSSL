#include "rsa.hpp"
#include "rsa_simd.hpp"
#include "cpu_features.hpp"
#include <cstring>
#include <cstdlib>
#include <vector>

namespace jpssl {

void batch_mont_mul_scalar(uint64_t* r, const uint64_t* a, const uint64_t* b,
                           const uint64_t* m, uint64_t mp, int K, int batch_size) {
    int t_len = 2 * K + 2;
    uint64_t* t = new uint64_t[batch_size * t_len]();
    uint64_t carry;

    for (int i = 0; i < K; ++i) {
        for (int msg = 0; msg < batch_size; ++msg) carry = 0;
        for (int msg = 0; msg < batch_size; ++msg) {
            const uint64_t* a_msg = a + msg * K;
            const uint64_t* b_msg = b + msg * K;
            uint64_t* t_msg = t + msg * t_len;
            carry = 0;
            uint64_t ai = a_msg[i];
            for (int j = 0; j < K; ++j) {
                __uint128_t p = (__uint128_t)ai * b_msg[j] + t_msg[i + j] + carry;
                t_msg[i + j] = (uint64_t)p;
                carry = (uint64_t)(p >> 64);
            }
            uint64_t sc = t_msg[i + K] + carry;
            t_msg[i + K] = sc;
            if (sc < carry) {
                int idx = i + K + 1;
                while (true) {
                    uint64_t s2 = t_msg[idx] + 1;
                    t_msg[idx] = s2;
                    if (s2) break;
                    ++idx;
                }
            }
        }
        for (int msg = 0; msg < batch_size; ++msg) {
            uint64_t* t_msg = t + msg * t_len;
            uint64_t u = t_msg[i] * mp;
            carry = 0;
            for (int j = 0; j < K; ++j) {
                __uint128_t s = (__uint128_t)u * m[j] + t_msg[i + j] + carry;
                t_msg[i + j] = (uint64_t)s;
                carry = (uint64_t)(s >> 64);
            }
            int idx = i + K;
            while (carry) {
                __uint128_t s = (__uint128_t)t_msg[idx] + carry;
                t_msg[idx] = (uint64_t)s;
                carry = (uint64_t)(s >> 64);
                ++idx;
            }
        }
    }

    for (int msg = 0; msg < batch_size; ++msg) {
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

void batch_modpow_scalar(uint64_t* r, const uint64_t* bases,
                         const uint64_t* exp, const uint64_t* mod,
                         const uint64_t* R2, const uint64_t* R_mod_m,
                         uint64_t mp, int K, int exp_bits, int batch_size) {
    int t_len = 2 * K + 2;
    uint64_t* bm = new uint64_t[batch_size * K];
    uint64_t* rm = new uint64_t[batch_size * K];
    uint64_t* t = new uint64_t[batch_size * t_len]();
    uint64_t carry;

    for (int msg = 0; msg < batch_size; ++msg) {
        uint64_t* rm_msg = rm + msg * K;
        for (int i = 0; i < K; ++i) rm_msg[i] = R_mod_m[i];
    }

    // To Montgomery: bm = mont_mul(base, R2)
    for (int msg = 0; msg < batch_size; ++msg) {
        memset(t + msg * t_len, 0, t_len * 8);
        carry = 0;
        for (int i = 0; i < K; ++i) {
            uint64_t* t_msg = t + msg * t_len;
            carry = 0;
            uint64_t ai = bases[msg * K + i];
            for (int j = 0; j < K; ++j) {
                __uint128_t p = (__uint128_t)ai * R2[j] + t_msg[i + j] + carry;
                t_msg[i + j] = (uint64_t)p;
                carry = (uint64_t)(p >> 64);
            }
            uint64_t sc = t_msg[i + K] + carry;
            t_msg[i + K] = sc;
            if (sc < carry) {
                int idx = i + K + 1;
                while (true) {
                    uint64_t s2 = t_msg[idx] + 1;
                    t_msg[idx] = s2;
                    if (s2) break;
                    ++idx;
                }
            }

            uint64_t u = t_msg[i] * mp;
            carry = 0;
            for (int j = 0; j < K; ++j) {
                __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry;
                t_msg[i + j] = (uint64_t)s;
                carry = (uint64_t)(s >> 64);
            }
            int idx = i + K;
            while (carry) {
                __uint128_t s = (__uint128_t)t_msg[idx] + carry;
                t_msg[idx] = (uint64_t)s;
                carry = (uint64_t)(s >> 64);
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
        int bbit = bit % 64;
        int e_bit = (exp[w] >> bbit) & 1;

        memset(t, 0, batch_size * t_len * 8);
        for (int msg = 0; msg < batch_size; ++msg) {
            uint64_t* rm_msg = rm + msg * K;
            uint64_t* t_msg = t + msg * t_len;
            carry = 0;
            for (int i = 0; i < K; ++i) {
                carry = 0;
                for (int j = 0; j < K; ++j) {
                    __uint128_t p = (__uint128_t)rm_msg[i] * rm_msg[j]
                                  + t_msg[i + j] + carry;
                    t_msg[i + j] = (uint64_t)p;
                    carry = (uint64_t)(p >> 64);
                }
                uint64_t sc = t_msg[i + K] + carry;
                t_msg[i + K] = sc;
                if (sc < carry) {
                    int idx = i + K + 1;
                    while (true) {
                        uint64_t s2 = t_msg[idx] + 1;
                        t_msg[idx] = s2;
                        if (s2) break;
                        ++idx;
                    }
                }
                uint64_t u = t_msg[i] * mp;
                carry = 0;
                for (int j = 0; j < K; ++j) {
                    __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry;
                    t_msg[i + j] = (uint64_t)s;
                    carry = (uint64_t)(s >> 64);
                }
                int idx = i + K;
                while (carry) {
                    __uint128_t s = (__uint128_t)t_msg[idx] + carry;
                    t_msg[idx] = (uint64_t)s;
                    carry = (uint64_t)(s >> 64);
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
            memset(t, 0, batch_size * t_len * 8);
            for (int msg = 0; msg < batch_size; ++msg) {
                uint64_t* rm_msg = rm + msg * K;
                uint64_t* bm_msg = bm + msg * K;
                uint64_t* t_msg = t + msg * t_len;
                carry = 0;
                for (int i = 0; i < K; ++i) {
                    carry = 0;
                    for (int j = 0; j < K; ++j) {
                        __uint128_t p = (__uint128_t)rm_msg[i] * bm_msg[j]
                                      + t_msg[i + j] + carry;
                        t_msg[i + j] = (uint64_t)p;
                        carry = (uint64_t)(p >> 64);
                    }
                    uint64_t sc = t_msg[i + K] + carry;
                    t_msg[i + K] = sc;
                    if (sc < carry) {
                        int idx = i + K + 1;
                        while (true) {
                            uint64_t s2 = t_msg[idx] + 1;
                            t_msg[idx] = s2;
                            if (s2) break;
                            ++idx;
                        }
                    }
                    uint64_t u = t_msg[i] * mp;
                    carry = 0;
                    for (int j = 0; j < K; ++j) {
                        __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry;
                        t_msg[i + j] = (uint64_t)s;
                        carry = (uint64_t)(s >> 64);
                    }
                    int idx = i + K;
                    while (carry) {
                        __uint128_t s = (__uint128_t)t_msg[idx] + carry;
                        t_msg[idx] = (uint64_t)s;
                        carry = (uint64_t)(s >> 64);
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
    for (int msg = 0; msg < batch_size; ++msg) {
        uint64_t one[64] = {};
        one[0] = 1;
        memset(t + msg * t_len, 0, t_len * 8);
        uint64_t* rm_msg = rm + msg * K;
        uint64_t* t_msg = t + msg * t_len;
        carry = 0;
        for (int i = 0; i < K; ++i) {
            carry = 0;
            for (int j = 0; j < K; ++j) {
                __uint128_t p = (__uint128_t)rm_msg[i] * one[j]
                              + t_msg[i + j] + carry;
                t_msg[i + j] = (uint64_t)p;
                carry = (uint64_t)(p >> 64);
            }
            uint64_t sc = t_msg[i + K] + carry;
            t_msg[i + K] = sc;
            if (sc < carry) {
                int idx = i + K + 1;
                while (true) {
                    uint64_t s2 = t_msg[idx] + 1;
                    t_msg[idx] = s2;
                    if (s2) break;
                    ++idx;
                }
            }
            uint64_t u = t_msg[i] * mp;
            carry = 0;
            for (int j = 0; j < K; ++j) {
                __uint128_t s = (__uint128_t)u * mod[j] + t_msg[i + j] + carry;
                t_msg[i + j] = (uint64_t)s;
                carry = (uint64_t)(s >> 64);
            }
            int idx = i + K;
            while (carry) {
                __uint128_t s = (__uint128_t)t_msg[idx] + carry;
                t_msg[idx] = (uint64_t)s;
                carry = (uint64_t)(s >> 64);
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

bool pkcs1_unpad(const uint8_t* block, size_t blen, std::vector<uint8_t>& pt) {
    if (blen < 11) return false;
    if (block[0] != 0 || block[1] != 2) return false;
    size_t sep = 2;
    while (sep < blen && block[sep] != 0) ++sep;
    if (sep >= blen - 1) return false;
    pt.assign(block + sep + 1, block + blen);
    return true;
}

void rsa_batch_decrypt_dispatch(const uint64_t* mod, const uint64_t* exp,
                                const uint64_t* R2, const uint64_t* R_mod_m,
                                uint64_t mp,
                                const uint8_t* cts, uint8_t* pts,
                                size_t count, int K, int exp_bits) {
    auto features = cpu_features::detect();

    int batch_size = 0;
    void (*modpow_fn)(uint64_t*, const uint64_t*, const uint64_t*,
                      const uint64_t*, const uint64_t*, const uint64_t*,
                      uint64_t, int, int) = nullptr;

    if (features.avx512 && count >= 8) {
        batch_size = 8;
        modpow_fn = batch_modpow_avx512;
    } else if (features.avx2 && count >= 4) {
        batch_size = 4;
        modpow_fn = batch_modpow_avx2;
    } else {
        batch_size = 1;
    }

    size_t pos = 0;
    while (pos < count) {
        size_t remaining = count - pos;
        size_t cur_batch = (modpow_fn && remaining >= (size_t)batch_size)
                           ? (size_t)batch_size : 1;

        uint64_t* bases = new uint64_t[cur_batch * K];
        uint64_t* results = new uint64_t[cur_batch * K];

        for (size_t i = 0; i < cur_batch; ++i) {
            const uint8_t* ct = cts + (pos + i) * K * 8;
            uint64_t* base = bases + i * K;
            for (int j = 0; j < K; ++j) {
                uint64_t v = 0;
                for (int k = 0; k < 8; ++k) {
                    v = (v << 8) | ct[j * 8 + k];
                }
                base[K - 1 - j] = v;
            }
        }

        if (cur_batch == 1) {
            batch_modpow_scalar(results, bases, exp, mod, R2, R_mod_m,
                                mp, K, exp_bits, 1);
        } else if (cur_batch == 4) {
            batch_modpow_avx2(results, bases, exp, mod, R2, R_mod_m,
                              mp, K, exp_bits);
        } else if (cur_batch == 8) {
            batch_modpow_avx512(results, bases, exp, mod, R2, R_mod_m,
                                mp, K, exp_bits);
        }

        for (size_t i = 0; i < cur_batch; ++i) {
            uint8_t* pt = pts + (pos + i) * K * 8;
            uint64_t* r_msg = results + i * K;
            for (int j = 0; j < K; ++j) {
                uint64_t v = r_msg[K - 1 - j];
                for (int k = 0; k < 8; ++k) {
                    pt[j * 8 + k] = (uint8_t)(v >> (56 - k * 8));
                }
            }
        }

        delete[] bases;
        delete[] results;
        pos += cur_batch;
    }
}

// ── Public API ──

size_t rsa_batch_decrypt(const rsa_private_key& key,
                         const uint8_t* cts, uint8_t* pts, size_t count) {
    mont_ctx mc = rsa_mont_init(key.n);
    int exp_bits = 0;
    for (int i = 31; i >= 0; --i) {
        if (key.d.d[i]) {
            uint64_t t = key.d.d[i];
            int b = 64;
            while (t) { t >>= 1; --b; }
            exp_bits = (i + 1) * 64 - b;
            break;
        }
    }
    rsa_batch_decrypt_dispatch(key.n.d, key.d.d,
                               mc.R2_mod_m.d, mc.R_mod_m.d, mc.m_prime,
                               cts, pts, count, 32, exp_bits);
    size_t success = 0;
    for (size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> pt;
        if (pkcs1_unpad(pts + i * 256, 256, pt)) {
            memmove(pts + success * 256, pts + i * 256, 256);
            ++success;
        }
    }
    return success;
}

size_t rsa4096_batch_decrypt(const rsa4096_private_key& key,
                             const uint8_t* cts, uint8_t* pts, size_t count) {
    mont_ctx4096 mc = rsa4096_mont_init(key.n);
    int exp_bits = 0;
    for (int i = 63; i >= 0; --i) {
        if (key.d.d[i]) {
            uint64_t t = key.d.d[i];
            int b = 64;
            while (t) { t >>= 1; --b; }
            exp_bits = (i + 1) * 64 - b;
            break;
        }
    }
    rsa_batch_decrypt_dispatch(key.n.d, key.d.d,
                               mc.R2_mod_m.d, mc.R_mod_m.d, mc.m_prime,
                               cts, pts, count, 64, exp_bits);
    size_t success = 0;
    for (size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> pt;
        if (pkcs1_unpad(pts + i * 512, 512, pt)) {
            memmove(pts + success * 512, pts + i * 512, 512);
            ++success;
        }
    }
    return success;
}

} // namespace jpssl
