/**
 * bench_base64.cpp -- base64 encode/decode benchmark: scalar vs AVX2 vs
 * AVX-512 vs the runtime-dispatched public API.
 *
 * Rows marked "avx2"/"avx512" measure the SIMD kernel plus the scalar tail
 * (encode) or the pure SIMD kernel (decode, canonical unpadded input).
 * "auto" measures the public base64_encode/base64_decode entry points,
 * including output allocation and padding handling.
 */
#include "base64.hpp"
#include "base64_internal.hpp"
#include "cpu_features.hpp"

#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <random>
#include <string>
#include <vector>

using namespace jpssl;

namespace {

using Clock = std::chrono::steady_clock;

/// Time `f` (which processes `bytes` bytes per call); returns bytes/second.
double bench_bytes(const std::function<void()>& f, size_t bytes) {
    f();  // warm-up
    double best = 0.0;
    int iters = 1;
    while (true) {
        const auto t0 = Clock::now();
        for (int i = 0; i < iters; ++i) f();
        const auto t1 = Clock::now();
        const double secs = std::chrono::duration<double>(t1 - t0).count();
        if (secs < 0.05 && iters < (1 << 24)) {
            iters *= 2;
            continue;
        }
        if (secs <= 0.0) {
            iters *= 2;
            continue;
        }
        const double rate = bytes * static_cast<double>(iters) / secs;
        if (rate > best) best = rate;
        if (secs >= 0.5 || iters >= (1 << 25)) break;
        iters *= 2;
    }
    return best;
}

std::vector<uint8_t> random_bytes(size_t n, uint32_t seed) {
    std::mt19937 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto& b : v) b = static_cast<uint8_t>(rng() & 0xff);
    return v;
}

struct Row {
    const char* name;
    double enc = 0.0;  // MiB/s
    double dec = 0.0;
};

void run_size(size_t len, std::vector<Row>& rows) {
    const auto data = random_bytes(len, 0x5eed);
    const size_t enc_len = ((len + 2) / 3) * 4;

    // Canonical (unpadded) encoding used by the decode benchmarks.
    std::string canon;
    canon.resize(((len / 3) * 4));
    detail::base64_encode_scalar(data.data(), (len / 3) * 3, &canon[0]);

    std::vector<char> out(enc_len);
    std::vector<uint8_t> dec_out((canon.size() / 4) * 3);
    std::vector<uint8_t> ref_dec = base64_decode(canon).value();

    const bool have_avx2 = cpu_has_avx2();
    const bool have_avx512 = cpu_has_avx512() && cpu_has_avx512bw();

    auto add = [&](const char* name, double e, double d) {
        rows.push_back({name, e / (1024.0 * 1024.0), d / (1024.0 * 1024.0)});
    };

    // scalar
    {
        detail::base64_encode_scalar(data.data(), len, out.data());
        std::string expect;
        expect.resize(enc_len);
        detail::base64_encode_scalar(data.data(), len, &expect[0]);
        if (std::string(out.data(), enc_len) != expect) std::abort();

        const double e = bench_bytes([&] {
            detail::base64_encode_scalar(data.data(), len, out.data());
        }, len);
        const double d = bench_bytes([&] {
            detail::base64_decode_scalar(&canon[0], canon.size(), dec_out.data());
        }, ref_dec.size());
        add("scalar", e, d);
    }

    // AVX2
    if (have_avx2) {
        const size_t p = detail::base64_encode_avx2(data.data(), len, out.data());
        detail::base64_encode_scalar(data.data() + p, len - p, out.data() + (p / 3) * 4);
        std::string expect;
        expect.resize(enc_len);
        detail::base64_encode_scalar(data.data(), len, &expect[0]);
        if (std::string(out.data(), enc_len) != expect) std::abort();

        const double e = bench_bytes([&] {
            const size_t q = detail::base64_encode_avx2(data.data(), len, out.data());
            detail::base64_encode_scalar(data.data() + q, len - q, out.data() + (q / 3) * 4);
        }, len);

        bool ok = detail::base64_decode_avx2(&canon[0], canon.size(), dec_out.data());
        if (!ok || dec_out != ref_dec) std::abort();
        const double d = bench_bytes([&] {
            detail::base64_decode_avx2(&canon[0], canon.size(), dec_out.data());
        }, ref_dec.size());
        add("avx2", e, d);
    } else {
        add("avx2", 0.0, 0.0);
    }

    // AVX-512
    if (have_avx512) {
        const size_t p = detail::base64_encode_avx512(data.data(), len, out.data());
        detail::base64_encode_scalar(data.data() + p, len - p, out.data() + (p / 3) * 4);
        std::string expect;
        expect.resize(enc_len);
        detail::base64_encode_scalar(data.data(), len, &expect[0]);
        if (std::string(out.data(), enc_len) != expect) std::abort();

        const double e = bench_bytes([&] {
            const size_t q = detail::base64_encode_avx512(data.data(), len, out.data());
            detail::base64_encode_scalar(data.data() + q, len - q, out.data() + (q / 3) * 4);
        }, len);

        bool ok = detail::base64_decode_avx512(&canon[0], canon.size(), dec_out.data());
        if (!ok || dec_out != ref_dec) std::abort();
        const double d = bench_bytes([&] {
            detail::base64_decode_avx512(&canon[0], canon.size(), dec_out.data());
        }, ref_dec.size());
        add("avx512", e, d);
    } else {
        add("avx512", 0.0, 0.0);
    }

    // auto dispatch (public API)
    {
        std::string expect;
        expect.resize(enc_len);
        detail::base64_encode_scalar(data.data(), len, &expect[0]);
        if (base64_encode(data) != expect) std::abort();
        if (!base64_decode(canon).has_value() || base64_decode(canon).value() != ref_dec) std::abort();
        const double e = bench_bytes([&] { (void)base64_encode(data); }, len);
        const double d = bench_bytes([&] { (void)base64_decode(canon); }, ref_dec.size());
        add("auto", e, d);
    }
}

} // namespace

int main() {
    // Multiples of 48 so canonical encodings are exact multiples of 64 chars,
    // letting the AVX2/AVX-512 decode kernels run on the whole buffer.
    const size_t sizes[] = {96, 1536, 65520, 1048560};
    for (size_t s : sizes) {
        std::vector<Row> rows;
        run_size(s, rows);

        std::printf("\n== base64, %zu input bytes ==\n", s);
        std::printf("  %-8s %12s %12s\n", "impl", "encode MiB/s", "decode MiB/s");
        double scalar_e = 0, scalar_d = 0;
        for (const auto& r : rows) {
            if (std::string(r.name) == "scalar") { scalar_e = r.enc; scalar_d = r.dec; }
            if (r.enc == 0.0 && r.dec == 0.0) {
                std::printf("  %-8s %12s %12s\n", r.name, "n/a", "n/a");
            } else {
                std::printf("  %-8s %12.1f %12.1f\n", r.name, r.enc, r.dec);
            }
        }
        for (const auto& r : rows) {
            if (r.enc == 0.0 && r.dec == 0.0) continue;
            if (std::string(r.name) == "scalar") continue;
            std::printf("    %-6s x%.2f enc / x%.2f dec vs scalar\n",
                        r.name,
                        scalar_e > 0 ? r.enc / scalar_e : 0.0,
                        scalar_d > 0 ? r.dec / scalar_d : 0.0);
        }
    }
    return 0;
}
