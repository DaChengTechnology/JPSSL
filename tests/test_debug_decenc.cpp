// Diagnostic: check basepoint encoding, d constant, and basic point ops
#include "ed25519.hpp"
#include "fe_25519.hpp"
#include "sha512.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl;
using namespace fe_impl;

static void hex(const char* label, const uint8_t* d, int n) {
    printf("%s: ", label);
    for (int i=0;i<n;i++) printf("%02x",d[i]);
    printf("\n");
}

// Forward declarations
struct ge_p3 { fe X, Y, Z, T; };
struct ge_p2 { fe X, Y, Z; };
struct ge_p1p1 { fe X, Y, Z, T; };
struct ge_precomp { fe y_plus_x, y_minus_x, xy2d; };

extern "C" {
    // These are defined in ed25519.cpp's anonymous namespace, but we can include the .cpp
}

int main() {
    // 1. Check basepoint encoding
    const uint8_t* bp_bytes = (const uint8_t*)"\x1a\xd5\x25\x8f\x60\x2d\x56\xc9\xb2\xa7\x25\x95\x60\xc7\x2c\x69\x5c\xdc\xd6\xfd\x31\xe2\xa4\xc0\xfe\x53\x6e\xcd\xd3\x36\x69\x21";
    printf("=== Basepoint Bx bytes ===\n");
    hex("Bx (jpssl)", bp_bytes, 32);
    
    const uint8_t* by_bytes = (const uint8_t*)"\x58\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66";
    printf("\n=== Basepoint By bytes ===\n");
    hex("By (jpssl)", by_bytes, 32);
    
    // Expected By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
    // In little-endian, this should be 0x58 0x66 0x66 ... (4/5 mod p)
    // Let me verify: 4/5 mod p
    printf("\n=== Check d constant ===\n");
    const uint8_t* db = (const uint8_t*)"\xa3\x78\x59\x13\xca\x4d\xeb\x75\xab\xd8\x41\x41\x4d\x0a\x70\x00\x98\xe8\x79\x77\x79\x40\xc7\x8c\x73\xfe\x6f\x2b\xee\x6c\x03\x52";
    hex("d (jpssl)", db, 32);
    
    // Expected d = -121665/121666 mod p
    // d in little-endian should be: a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352
    // Which matches what we have
    
    // 2. Test: decode pubkey A, check roundtrip
    printf("\n=== Pubkey A decode/encode roundtrip ===\n");
    uint8_t pub[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    hex("A (input)", pub, 32);
    
    ge_p3 A_pt;
    int ret = ge_frombytes(&A_pt, pub);
    printf("ge_frombytes ret: %d (0=OK)\n", ret);
    
    uint8_t A_reenc[32];
    ge_tobytes(A_reenc, &A_pt);
    hex("A (re-encoded)", A_reenc, 32);
    printf("Roundtrip match: %s\n", memcmp(pub, A_reenc, 32)==0?"YES":"NO");
    
    // 3. Test: decode basepoint R from signature
    printf("\n=== R decode/encode from sig ===\n");
    uint8_t R_enc[32] = {0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55};
    hex("R (input)", R_enc, 32);
    
    ge_p3 R_pt;
    ret = ge_frombytes(&R_pt, R_enc);
    printf("ge_frombytes ret: %d\n", ret);
    
    uint8_t R_reenc[32];
    ge_tobytes(R_reenc, &R_pt);
    hex("R (re-encoded)", R_reenc, 32);
    printf("Roundtrip match: %s\n", memcmp(R_enc, R_reenc, 32)==0?"YES":"NO");
    
    // 4. Test ge_frombytes with negative case
    printf("\n=== Test ge_frombytes negative check ===\n");
    // R bytes have bit 7 of last byte = 0 (0x55), so X should be non-negative
    // A bytes have bit 7 of last byte = 0 (0x1a), so X should be non-negative
    printf("A last byte: %02x, bit7=%d\n", pub[31], pub[31]>>7);
    printf("R last byte: %02x, bit7=%d\n", R_enc[31], R_enc[31]>>7);
    
    return 0;
}
