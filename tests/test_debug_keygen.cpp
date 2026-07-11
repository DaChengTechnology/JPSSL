#include <cstdio>
#include <cstdint>
#include <cstring>

// Include the internal headers
#include "fe_25519.hpp"
#include "sha512.hpp"

// Copy the needed ge/ed25519 internal functions for tracing
// Rather than duplicating code, let's call the public API and dump intermediates

namespace jpssl {
// Declare internal functions we need to trace
namespace {
using fe = fe_impl::fe;
using fe_impl::fe_frombytes;
using fe_impl::fe_tobytes;
using fe_impl::fe_copy;
using fe_impl::fe_1;
using fe_impl::fe_0;
using fe_impl::fe_add;
using fe_impl::fe_sub;
using fe_impl::fe_mul;
using fe_impl::fe_sq;
using fe_impl::fe_invert;
using fe_impl::fe_isnegative;

struct ge_p3 { fe X, Y, Z, T; };
struct ge_p2 { fe X, Y, Z; };
struct ge_p1p1 { fe X, Y, Z, T; };

static void ge_p3_to_p2(ge_p2* r, const ge_p3* p) {
    fe_copy(r->X, p->X); fe_copy(r->Y, p->Y); fe_copy(r->Z, p->Z);
}

static void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

static void ge_p2_dbl(ge_p1p1* r, const ge_p2* p) {
    fe a, b, c, e, g, f, h, t;
    fe_sq(a, p->X); fe_sq(b, p->Y); fe_sq(c, p->Z);
    fe_add(c, c, c);
    fe_add(t, p->X, p->Y); fe_sq(t, t);
    fe_sub(t, t, a); fe_sub(e, t, b);
    fe_sub(g, b, a); fe_sub(f, g, c);
    fe_add(h, a, b); fe_neg(h, h);
    fe_mul(r->X, e, f); fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h); fe_mul(r->Z, f, g);
}

static void ge_p3_dbl(ge_p1p1* r, const ge_p3* p) {
    ge_p2 q; ge_p3_to_p2(&q, p); ge_p2_dbl(r, &q);
}

// d2 and d from fe_frombytes
static const int32_t* d_limbs() {
    static fe d; static bool init = false;
    if (!init) { init = true;
        uint8_t bytes[32] = {163,120,89,19,202,77,235,117,171,216,65,65,77,10,112,0,152,232,121,119,121,64,199,140,115,254,111,43,238,108,3,82};
        fe_frombytes(d, bytes);
    } return d;
}
static const int32_t* d2_limbs() {
    static fe d; static bool init = false;
    if (!init) { init = true;
        uint8_t bytes[32] = {89,241,178,38,148,155,214,235,86,177,131,130,154,20,224,0,48,209,243,238,242,128,142,25,231,252,223,86,220,217,6,36};
        fe_frombytes(d, bytes);
    } return d;
}

static void ge_add(ge_p1p1* r, const ge_p3* p, const ge_p3* q) {
    fe a, b, c, d, e, f, g, h, t;
    fe_sub(a, p->Y, p->X); fe_sub(t, q->Y, q->X); fe_mul(a, a, t);
    fe_add(b, p->Y, p->X); fe_add(t, q->Y, q->X); fe_mul(b, b, t);
    fe_mul(c, p->T, q->T); fe_mul(c, c, d2_limbs());
    fe_mul(d, p->Z, q->Z); fe_add(d, d, d);
    fe_sub(e, b, a); fe_sub(f, d, c);
    fe_add(g, d, c); fe_add(h, b, a);
    fe_mul(r->X, e, f); fe_mul(r->Y, g, h);
    fe_mul(r->T, e, h); fe_mul(r->Z, f, g);
}

static void ge_p3_0(ge_p3* h) { fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T); }
static void ge_p3_to_p3(ge_p3* r, const ge_p3* p) {
    fe_copy(r->X, p->X); fe_copy(r->Y, p->Y);
    fe_copy(r->Z, p->Z); fe_copy(r->T, p->T);
}

void dump_fe(const char* label, const fe f) {
    uint8_t bytes[32];
    fe_tobytes(bytes, f);
    printf("  %s: ", label);
    for (int i = 0; i < 32; i++) printf("%02x", bytes[i]);
    printf("  limbs: %d %d %d %d %d %d %d %d %d %d\n",
        f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9]);
}

// Basepoint
static const int32_t* Bx_limbs() {
    static fe x; static bool init = false;
    if (!init) { init = true;
        uint8_t bytes[32] = {148,59,97,128,114,104,141,41,245,123,43,86,22,125,36,239,189,229,9,244,90,53,236,174,94,133,111,205,211,54,105,33};
        fe_frombytes(x, bytes);
    } return x;
}
static const int32_t* By_limbs() {
    static fe y; static bool init = false;
    if (!init) { init = true;
        uint8_t bytes[32] = {88,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102};
        fe_frombytes(y, bytes);
    } return y;
}

static ge_p3* ge_get_basepoint() {
    static ge_p3 B; static int init = 0;
    if (!init) { init = 1;
        fe_copy(B.X, Bx_limbs()); fe_copy(B.Y, By_limbs());
        fe_1(B.Z); fe_mul(B.T, B.X, B.Y);
    } return &B;
}

static void ge_scalarmult_base(ge_p3* r, const uint8_t scalar[32]) {
    printf("\n=== ge_scalarmult_base ===\n");
    const ge_p3* B = ge_get_basepoint();
    dump_fe("B.X", B->X);
    dump_fe("B.Y", B->Y);
    dump_fe("B.Z", B->Z);
    dump_fe("B.T", B->T);
    
    int first = -1;
    for (int i = 255; i >= 0; i--)
        if ((scalar[i >> 3] >> (i & 7)) & 1) { first = i; break; }
    printf("first bit = %d\n", first);
    if (first < 0) { ge_p3_0(r); return; }
    
    ge_p3_to_p3(r, B);
    dump_fe("r->X (init)", r->X);
    dump_fe("r->Y (init)", r->Y);
    
    for (int i = first - 1; i >= first - 3 && i >= 0; i--) {
        ge_p1p1 t;
        ge_p3_dbl(&t, r);
        ge_p1p1_to_p3(r, &t);
        if ((scalar[i >> 3] >> (i & 7)) & 1) {
            ge_p1p1 t2;
            ge_add(&t2, r, B);
            ge_p1p1_to_p3(r, &t2);
        }
    }
    printf("After first 3 iterations:\n");
    dump_fe("r->X", r->X);
    dump_fe("r->Y", r->Y);
}

} // anon namespace
} // jpssl

static void hexb(const char* label, const uint8_t* d, int n) {
    printf("  %s: ", label);
    for (int i = 0; i < n; i++) printf("%02x", d[i]);
    printf("\n");
}

int main() {
    using namespace jpssl;
    
    // Test: scalar multiplication of basepoint by known scalar
    // Use scalar = 1 to get the basepoint itself
    uint8_t scalar_one[32] = {1};
    ge_p3 result;
    ge_scalarmult_base(&result, scalar_one);
    
    // Check: with scalar=1, the result should be exactly the basepoint
    printf("\n=== Verify: 1 * B == B ===\n");
    uint8_t result_bytes[32];
    {
        fe recip, x, y;
        fe_invert(recip, result.Z);
        fe_mul(x, result.X, recip);
        fe_mul(y, result.Y, recip);
        fe_tobytes(result_bytes, y);
        if (fe_isnegative(x)) result_bytes[31] |= 0x80;
    }
    hexb("1*B encoded", result_bytes, 32);
    
    // Expected basepoint encoding:
    // y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
    // sign bit for x is 0 (x is positive)
    uint8_t expected_by[32] = {
        0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
    };
    hexb("expected 1*B", expected_by, 32);
    bool match = memcmp(result_bytes, expected_by, 32) == 0;
    printf("  match: %s\n", match ? "YES" : "NO");
    
    if (!match) {
        // Also check the x coordinate
        fe_tobytes(result_bytes, x); // x (without sign bit)
        hexb("x coordinate", result_bytes, 32);
        
        // Expected x: 15112221349535891490771889845789546913814871384922459474716389586016139295636
        uint8_t expected_bx[32] = {
            0x94,0x3b,0x61,0x80,0x72,0x68,0x8d,0x29,
            0xf5,0x7b,0x2b,0x56,0x16,0x7d,0x24,0xef,
            0xbd,0xe5,0x09,0xf4,0x5a,0x35,0xec,0xae,
            0x5e,0x85,0x6f,0xcd,0xd3,0x36,0x69,0x21
        };
        hexb("expected bx", expected_bx, 32);
    }
    
    return match ? 0 : 1;
}
