// Test: ed25519 batch verify
#include "ed25519_batch.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <array>
#include <vector>
using namespace jpssl;

int main() {
    bool all_ok = true;
#define CHECK(name, cond) do { \
        bool __ok = (cond); \
        printf("%-24s %s\n", name, __ok ? "PASS" : "FAIL"); \
        all_ok = all_ok && __ok; \
    } while (0)

    int bs = ed25519_batch_size();
    printf("Batch size: %d\n", bs);
    
    // Generate 16 keypairs and signatures
    const int N = 16;
    uint8_t pubs[N][32];
    uint8_t privs[N][64];
    uint8_t sigs[N][64];
    const char* msgs[N];
    size_t msg_lens[N];
    
    for (int i = 0; i < N; i++) {
        jpssl::ed25519_keygen(pubs[i], privs[i]);
        msgs[i] = "batch test message";
        msg_lens[i] = strlen(msgs[i]);
        jpssl::ed25519_sign(privs[i], (const uint8_t*)msgs[i], msg_lens[i], sigs[i]);
    }
    
    // Setup pointer arrays
    const uint8_t* pub_ptrs[N];
    const uint8_t* msg_ptrs[N];
    const uint8_t* sig_ptrs[N];
    for (int i = 0; i < N; i++) {
        pub_ptrs[i] = pubs[i];
        msg_ptrs[i] = (const uint8_t*)msgs[i];
        sig_ptrs[i] = sigs[i];
    }
    
    // Test 1: all valid
    bool ok = ed25519_batch_verify(pub_ptrs, msg_ptrs, msg_lens, sig_ptrs, N);
    CHECK("Batch 16 valid", ok);
    
    // Test 2: tamper one signature
    sigs[3][0] ^= 1;
    ok = ed25519_batch_verify(pub_ptrs, msg_ptrs, msg_lens, sig_ptrs, N);
    CHECK("Batch 16 tampered (FAIL)", !ok);
    sigs[3][0] ^= 1; // restore
    
    // Test 3: small batch (3 items)
    ok = ed25519_batch_verify(pub_ptrs, msg_ptrs, msg_lens, sig_ptrs, 3);
    CHECK("Batch 3 valid", ok);
    
    // Test 4: empty message
    uint8_t pub_e[32], priv_e[64];
    jpssl::ed25519_keygen(pub_e, priv_e);
    uint8_t sig_e[64];
    jpssl::ed25519_sign(priv_e, nullptr, 0, sig_e);
    const uint8_t* e_pub = pub_e;
    const uint8_t* e_msg = nullptr;
    size_t e_len = 0;
    const uint8_t* e_sig = sig_e;
    ok = ed25519_batch_verify(&e_pub, &e_msg, &e_len, &e_sig, 1);
    CHECK("Batch 1 empty msg", ok);

    // Test 5: 恰好一个分块 (128) / 跨分块 (129)
    constexpr int B = 128;
    std::vector<std::array<uint8_t, 32>> pubs2(B + 1);
    std::vector<std::array<uint8_t, 64>> privs2(B + 1);
    std::vector<std::array<uint8_t, 64>> sigs2(B + 1);
    std::vector<const uint8_t*> pp(B + 1), sp(B + 1);
    std::vector<const uint8_t*> mm(B + 1, (const uint8_t*)"chunk boundary");
    std::vector<size_t> ll(B + 1, 14);
    for (int i = 0; i <= B; ++i) {
        jpssl::ed25519_keygen(pubs2[i].data(), privs2[i].data());
        jpssl::ed25519_sign(privs2[i].data(), (const uint8_t*)"chunk boundary", 14, sigs2[i].data());
        pp[i] = pubs2[i].data();
        sp[i] = sigs2[i].data();
    }
    ok = ed25519_batch_verify(pp.data(), mm.data(), ll.data(), sp.data(), B);
    CHECK("Batch 128 (1 chunk)", ok);
    ok = ed25519_batch_verify(pp.data(), mm.data(), ll.data(), sp.data(), B + 1);
    CHECK("Batch 129 (2 chunks)", ok);
    sigs2[64][0] ^= 0x80;
    ok = ed25519_batch_verify(pp.data(), mm.data(), ll.data(), sp.data(), B + 1);
    CHECK("Batch 129 tampered (FAIL)", !ok);
    sigs2[64][0] ^= 0x80;

    // Test 6: s >= l（非规范签名）必须拒绝
    uint8_t sig_bad[64];
    memcpy(sig_bad, sigs2[0].data(), 64);
    memcpy(sig_bad + 32,
           "\xed\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10", 32);
    const uint8_t* bad_p = pubs2[0].data();
    const uint8_t* bad_s = sig_bad;
    ok = ed25519_batch_verify(&bad_p, mm.data(), ll.data(), &bad_s, 1);
    CHECK("Batch s==l rejected (FAIL)", !ok);

    // Test 7: 非法公钥编码（y >= p）必须拒绝
    uint8_t pub_bad[32];
    memcpy(pub_bad, pubs2[0].data(), 32);
    memset(pub_bad, 0xff, 32);
    const uint8_t* bad_p2 = pub_bad;
    const uint8_t* ok_s = sigs2[0].data();
    ok = ed25519_batch_verify(&bad_p2, mm.data(), ll.data(), &ok_s, 1);
    CHECK("Batch bad pub rejected (FAIL)", !ok);
    
    printf("\n%s\n", all_ok ? "ALL PASSED" : "SOME FAILED");
    return 0;
}
