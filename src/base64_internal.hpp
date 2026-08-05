#pragma once
/**
 * base64_internal.hpp -- internal (non-public) base64 entry points.
 *
 * Used by base64.cpp for runtime dispatch and by tests/benchmarks to
 * exercise each implementation individually.
 */
#include <cstddef>
#include <cstdint>

namespace jpssl {
namespace detail {

/// Scalar RFC 4648 encode of `len` bytes.  Writes ((len + 2) / 3) * 4 bytes
/// (including any '=' padding) to `out`; the buffer must be large enough.
void base64_encode_scalar(const uint8_t* data, size_t len, char* out);

/// AVX2 encode: processes complete 24-byte groups while the unaligned loads
/// stay in bounds (i + 28 <= len).  Returns the number of input bytes encoded;
/// the caller finishes the tail with the scalar path.
size_t base64_encode_avx2(const uint8_t* data, size_t len, char* out);

/// AVX-512 encode: processes complete 48-byte groups while in bounds.
/// Returns the number of input bytes encoded.
size_t base64_encode_avx512(const uint8_t* data, size_t len, char* out);

/// Scalar RFC 4648 decode of `len` chars (len % 4 == 0, no '=' padding).
/// Writes (len / 4) * 3 bytes to `out`.  Returns false on an invalid character.
bool base64_decode_scalar(const char* text, size_t len, uint8_t* out);

/// AVX2 decode: processes exactly `len` chars, which must be a multiple of 32.
/// Writes (len / 4) * 3 bytes to `out`.  Returns false on an invalid character.
bool base64_decode_avx2(const char* text, size_t len, uint8_t* out);

/// AVX-512 decode: processes exactly `len` chars, which must be a multiple of 64.
/// Writes (len / 4) * 3 bytes to `out`.  Returns false on an invalid character.
bool base64_decode_avx512(const char* text, size_t len, uint8_t* out);

} // namespace detail
} // namespace jpssl
