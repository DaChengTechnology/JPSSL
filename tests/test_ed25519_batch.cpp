// Test: ed25519 batch verify
#include "ed25519_batch.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
using namespace jpssl;

int main() {
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
    printf("Batch %d valid:      %s\n", N, ok ? "PASS" : "FAIL");
    
    // Test 2: tamper one signature
    sigs[3][0] ^= 1;
    ok = ed25519_batch_verify(pub_ptrs, msg_ptrs, msg_lens, sig_ptrs, N);
    printf("Batch %d tampered:   %s (expect FAIL)\n", N, ok ? "FAIL" : "PASS");
    sigs[3][0] ^= 1; // restore
    
    // Test 3: small batch (3 items)
    ok = ed25519_batch_verify(pub_ptrs, msg_ptrs, msg_lens, sig_ptrs, 3);
    printf("Batch 3 valid:       %s\n", ok ? "PASS" : "FAIL");
    
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
    printf("Batch 1 empty msg:   %s\n", ok ? "PASS" : "FAIL");
    
    printf("\n%s\n", ok ? "ALL PASSED" : "SOME FAILED");
    return 0;
}
