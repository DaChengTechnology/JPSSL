/**
 * rsa_musa.cpp — RSA MUSA GPU 封装
 *
 * 调用 rsa_gpu.mu kernel 进行批量 Montgomery 模幂
 */

#include "rsa.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <musa_runtime.h>

namespace jpssl {

#define RSA_GPU_CHECK(call) do { \
    musaError_t e = (call); \
    if (e != musaSuccess) { std::fprintf(stderr,"RSA GPU error: %s\n",musaGetErrorString(e)); abort(); } \
} while(0)

extern "C" void musa_rsa_gpu_init(const uint64_t* mod, const uint64_t* exp,
                                  uint64_t m_prime, const uint64_t* R2);
extern "C" void launch_rsa_batch_decrypt(const uint64_t* d_c, uint64_t* d_p,
                                         int count, int threads, musaStream_t stream);

struct musa_rsa_pool {
    rsa_private_key key;
    size_t batch_size;
    uint64_t* d_ciphers = nullptr;
    uint64_t* d_plains  = nullptr;
};

musa_rsa_pool* musa_rsa_pool_create(const rsa_private_key& prv, size_t batch_size) {
    auto* p = new musa_rsa_pool();
    p->key = prv;
    p->batch_size = batch_size;

    auto mctx = rsa_mont_init(prv.n);
    musa_rsa_gpu_init(prv.n.d, prv.d.d, mctx.m_prime, mctx.R2_mod_m.d);

    size_t bytes = batch_size * RSA_2048_WORDS * 8;
    RSA_GPU_CHECK(musaMalloc(&p->d_ciphers, bytes));
    RSA_GPU_CHECK(musaMalloc(&p->d_plains, bytes));
    return p;
}

void musa_rsa_pool_destroy(musa_rsa_pool* pool) {
    if (!pool) return;
    if (pool->d_ciphers) musaFree(pool->d_ciphers);
    if (pool->d_plains)  musaFree(pool->d_plains);
    delete pool;
}

void musa_rsa_batch_decrypt(musa_rsa_pool* pool,
                            const uint8_t* ciphers,
                            uint8_t* plains, size_t count) {
    if (count > pool->batch_size) count = pool->batch_size;
    size_t bytes = count * RSA_2048_WORDS * 8;
    RSA_GPU_CHECK(musaMemcpy(pool->d_ciphers, ciphers, bytes, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt(pool->d_ciphers, pool->d_plains, (int)count, 64, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    RSA_GPU_CHECK(musaMemcpy(plains, pool->d_plains, bytes, musaMemcpyDeviceToHost));
}

void musa_rsa_batch_modpow(const rsa_bignum& mod, const rsa_bignum& exp,
                           const mont_ctx& mctx,
                           const uint8_t* bases, uint8_t* results, size_t count) {
    musa_rsa_gpu_init(mod.d, exp.d, mctx.m_prime, mctx.R2_mod_m.d);
    size_t bytes = count * RSA_2048_WORDS * 8;
    uint64_t *d_c = nullptr, *d_p = nullptr;
    RSA_GPU_CHECK(musaMalloc(&d_c, bytes));
    RSA_GPU_CHECK(musaMalloc(&d_p, bytes));
    RSA_GPU_CHECK(musaMemcpy(d_c, bases, bytes, musaMemcpyHostToDevice));
    launch_rsa_batch_decrypt(d_c, d_p, (int)count, 64, nullptr);
    RSA_GPU_CHECK(musaDeviceSynchronize());
    RSA_GPU_CHECK(musaMemcpy(results, d_p, bytes, musaMemcpyDeviceToHost));
    RSA_GPU_CHECK(musaFree(d_c));
    RSA_GPU_CHECK(musaFree(d_p));
}

} // namespace jpssl
