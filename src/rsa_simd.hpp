#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <vector>

namespace jpssl {

void batch_mont_mul_scalar(uint64_t* r, const uint64_t* a, const uint64_t* b,
                           const uint64_t* m, uint64_t mp, int K, int batch_size);

void batch_modpow_scalar(uint64_t* r, const uint64_t* bases,
                         const uint64_t* exp, const uint64_t* mod,
                         const uint64_t* R2, const uint64_t* R_mod_m,
                         uint64_t mp, int K, int exp_bits, int batch_size);

// AVX2 (4-wide)
void batch_mont_mul_avx2(uint64_t* r, const uint64_t* a, const uint64_t* b,
                         const uint64_t* m, uint64_t mp, int K);
void batch_modpow_avx2(uint64_t* r, const uint64_t* bases,
                       const uint64_t* exp, const uint64_t* mod,
                       const uint64_t* R2, const uint64_t* R_mod_m,
                       uint64_t mp, int K, int exp_bits);

// AVX-512 (8-wide)
void batch_mont_mul_avx512(uint64_t* r, const uint64_t* a, const uint64_t* b,
                           const uint64_t* m, uint64_t mp, int K);
void batch_modpow_avx512(uint64_t* r, const uint64_t* bases,
                         const uint64_t* exp, const uint64_t* mod,
                         const uint64_t* R2, const uint64_t* R_mod_m,
                         uint64_t mp, int K, int exp_bits);

// Dispatch
void rsa_batch_decrypt_dispatch(const uint64_t* mod, const uint64_t* exp,
                                const uint64_t* R2, const uint64_t* R_mod_m,
                                uint64_t mp,
                                const uint8_t* cts, uint8_t* pts,
                                size_t count, int K, int exp_bits);

// Helper: PKCS#1 v1.5 unpad
bool pkcs1_unpad(const uint8_t* block, size_t blen, std::vector<uint8_t>& pt);

} // namespace jpssl
