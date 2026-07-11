/**
 * sha512_musa.cpp — MUSA GPU SHA-384/SHA-512 host-side wrapper
 */

#include "sha512.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <musa_runtime.h>

#define MUSA_CHECK(call) do { musaError_t err = (call); if (err != musaSuccess) { std::fprintf(stderr, "MUSA error at %s:%d - %s (code %d)\n", __FILE__, __LINE__, musaGetErrorString(err), (int)err); std::abort(); } } while (0)

namespace jpssl {

extern "C" void musa_sha512_gpu_init();
extern "C" void launch_sha512_gpu(
    const uint8_t* d_input, uint8_t* d_output,
    int num_msgs, int is_384,
    int threads_per_block, musaStream_t stream);

static constexpr int GPU_THREADS = 256;
static bool g_sha512_gpu_inited = false;

void musa_sha512_init() {
    musa_sha512_gpu_init();
    g_sha512_gpu_inited = true;
}

void musa_sha512_cleanup() {
    g_sha512_gpu_inited = false;
}

void musa_sha512_compute(const uint8_t* input, size_t input_len,
                         uint8_t* output, bool is_384) {
    if (!g_sha512_gpu_inited) {
        std::fprintf(stderr, "MUSA SHA-512 not initialized! Call musa_sha512_init() first.\n");
        std::abort();
    }
    if (input_len > 128) {
        std::fprintf(stderr, "MUSA SHA-512: input too large for single-block kernel (%zu > 128)\n", input_len);
        std::abort();
    }

    // Pad input to 128 bytes
    uint8_t padded[128] = {};
    std::memcpy(padded, input, input_len);
    padded[input_len] = 0x80;
    uint64_t bits = input_len * 8;
    padded[126] = (uint8_t)(bits >> 8);
    padded[127] = (uint8_t)(bits >> 0);

    uint8_t* d_in = nullptr;
    MUSA_CHECK(musaMalloc(&d_in, 128));
    MUSA_CHECK(musaMemcpy(d_in, padded, 128, musaMemcpyHostToDevice));

    size_t out_size = is_384 ? 48 : 64;
    uint8_t* d_out = nullptr;
    MUSA_CHECK(musaMalloc(&d_out, out_size));

    launch_sha512_gpu(d_in, d_out, 1, is_384 ? 1 : 0, GPU_THREADS, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(output, d_out, out_size, musaMemcpyDeviceToHost));

    MUSA_CHECK(musaFree(d_in));
    MUSA_CHECK(musaFree(d_out));
}

void musa_sha512_batch(const uint8_t* inputs, size_t input_len,
                       uint8_t* outputs, int num_msgs, bool is_384) {
    if (!g_sha512_gpu_inited) {
        std::fprintf(stderr, "MUSA SHA-512 not initialized!\n");
        std::abort();
    }
    if (input_len > 128) {
        std::fprintf(stderr, "MUSA SHA-512: input too large for single-block kernel\n");
        std::abort();
    }

    size_t out_size = is_384 ? 48 : 64;
    size_t batch_bytes = (size_t)num_msgs * 128;

    uint8_t* d_in = nullptr;
    uint8_t* d_out = nullptr;
    MUSA_CHECK(musaMalloc(&d_in, batch_bytes));
    MUSA_CHECK(musaMalloc(&d_out, (size_t)num_msgs * out_size));

    // Upload all inputs
    MUSA_CHECK(musaMemcpy(d_in, inputs, batch_bytes, musaMemcpyHostToDevice));

    launch_sha512_gpu(d_in, d_out, num_msgs, is_384 ? 1 : 0, GPU_THREADS, nullptr);
    MUSA_CHECK(musaDeviceSynchronize());
    MUSA_CHECK(musaMemcpy(outputs, d_out, (size_t)num_msgs * out_size, musaMemcpyDeviceToHost));

    MUSA_CHECK(musaFree(d_in));
    MUSA_CHECK(musaFree(d_out));
}

} // namespace jpssl
