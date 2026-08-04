/**
 * ed448.cpp - Ed448 signature algorithm (RFC 8032 5.2), public API.
 *
 * The core implementation lives in ed448_body.inc (shared with the
 * AVX2/AVX512 batch backends) and is included here in the ed448_cpu_impl
 * namespace. This file adds the public API plus debug/test wrappers that
 * convert between the public (X,Y,Z) point struct and the internal
 * extended-coordinate point (X,Y,Z,T).
 */
#include "ed448.hpp"
#include "sha3.hpp"
#include "rsa.hpp"
#include "fe_448.hpp"
#include <cstring>
#include <random>

namespace jpssl {
namespace ed448_cpu_impl {
#include "ed448_body.inc"
} // namespace ed448_cpu_impl
} // namespace jpssl

namespace jpssl {

// ---- public API ----

void ed448_keygen(uint8_t pub[57], uint8_t priv_seed[57]) {
    ed448_cpu_impl::ed448_keygen_impl(pub, priv_seed);
}

void ed448_generate_keypair(uint8_t pub[57], uint8_t priv[114]) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    for (int i = 0; i < 7; ++i) {
        uint64_t v = gen();
        memcpy(priv + i * 8, &v, 8);
    }
    priv[56] = (uint8_t)(gen() & 0xff);

    ed448_keygen(pub, priv);
    memcpy(priv + 57, pub, 57);
}

void ed448_sign(const uint8_t* priv, const uint8_t* msg, size_t msg_len,
                uint8_t sig[114]) {
    ed448_cpu_impl::ed448_sign_impl(priv, msg, msg_len, sig);
}

bool ed448_verify(const uint8_t pub[57], const uint8_t* msg, size_t msg_len,
                  const uint8_t sig[114]) {
    return ed448_cpu_impl::ed448_verify_impl(pub, msg, msg_len, sig);
}

// ---- debug / test wrappers (public ed448_point holds X,Y,Z) ----

namespace {
using namespace jpssl::fe448_impl;
using ExtPt = ed448_cpu_impl::ed448_point_ext;

void to_public(jpssl::ed448_point& out, const ExtPt& in) {
    fe448_copy(out.X, in.X);
    fe448_copy(out.Y, in.Y);
    fe448_copy(out.Z, in.Z);
}

void to_internal(ExtPt& out, const jpssl::ed448_point& in) {
    fe448_copy(out.X, in.X);
    fe448_copy(out.Y, in.Y);
    fe448_copy(out.Z, in.Z);
    fe448 z_inv;
    fe448_invert(z_inv, in.Z);
    fe448_mul(out.T, in.X, in.Y);
    fe448_mul(out.T, out.T, z_inv);
}
} // namespace

bool ed448_debug_decode(jpssl::ed448_point& P, const uint8_t in[57]) {
    ExtPt pp;
    bool ok = ed448_cpu_impl::point_decode(pp, in);
    if (ok) to_public(P, pp);
    return ok;
}

void ed448_debug_encode(const jpssl::ed448_point& P, uint8_t out[57]) {
    ExtPt pp;
    to_internal(pp, P);
    ed448_cpu_impl::point_encode(pp, out);
}

void ed448_debug_scalar_mult(jpssl::ed448_point& R, const uint8_t scalar[57],
                             const jpssl::ed448_point& P) {
    ExtPt pp, rr;
    to_internal(pp, P);
    ExtPt table[16];
    ed448_cpu_impl::point_table_build(table, pp);
    ed448_cpu_impl::scalar_mult_windows(rr, scalar, table);
    to_public(R, rr);
}

void ed448_debug_point_add(jpssl::ed448_point& R,
                           const jpssl::ed448_point& P,
                           const jpssl::ed448_point& Q) {
    ExtPt pp, qq, rr;
    to_internal(pp, P);
    to_internal(qq, Q);
    ed448_cpu_impl::point_add_ext(rr, pp, qq);
    to_public(R, rr);
}

void ed448_debug_point_double(jpssl::ed448_point& R,
                              const jpssl::ed448_point& P) {
    ExtPt pp, rr;
    to_internal(pp, P);
    ed448_cpu_impl::point_double_ext(rr, pp);
    to_public(R, rr);
}

const jpssl::ed448_point& ed448_debug_base_point() {
    static jpssl::ed448_point bp;
    static bool init = false;
    if (!init) {
        to_public(bp, ed448_cpu_impl::base_point());
        init = true;
    }
    return bp;
}

} // namespace jpssl
