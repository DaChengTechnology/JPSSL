/**
 * test_ed448_batch.cpp — Ed448 batch verification test
 */
#include "ed448_batch.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

using namespace jpssl;

int main() {
    bool all = true;
    const int N = 16; // test with 16 signatures

    // Prepare test data
    uint8_t pubs[N][57];
    uint8_t privs[N][114];
    uint8_t msgs[N][32];
    uint8_t sigs[N][114];

    const uint8_t* pub_ptrs[N];
    const uint8_t* msg_ptrs[N];
    size_t msg_lens[N];
    const uint8_t* sig_ptrs[N];

    for (int i = 0; i < N; i++) {
        ed448_generate_keypair(pubs[i], privs[i]);
        for (int j = 0; j < 32; j++) msgs[i][j] = (uint8_t)(i * 32 + j);
        ed448_sign(privs[i], msgs[i], 32, sigs[i]);

        pub_ptrs[i] = pubs[i];
        msg_ptrs[i] = msgs[i];
        msg_lens[i] = 32;
        sig_ptrs[i] = sigs[i];
    }

    // Test 1: all valid signatures
    bool ok = ed448_batch_verify(pub_ptrs, msg_ptrs, msg_lens, sig_ptrs, N);
    printf("[%s] Ed448 batch verify %d valid signatures\n", ok ? "PASS" : "FAIL", N);
    all &= ok;

    // Test 2: one invalid signature (tampered)
    uint8_t bad_sig[114];
    memcpy(bad_sig, sigs[0], 114);
    bad_sig[0] ^= 0x01;
    sig_ptrs[0] = bad_sig;
    ok = ed448_batch_verify(pub_ptrs, msg_ptrs, msg_lens, sig_ptrs, N);
    printf("[%s] Ed448 batch verify rejects tampered signature\n", !ok ? "PASS" : "FAIL");
    all &= !ok;

    // Test 3: batch size reporting
    int bs = ed448_batch_size();
    printf("[INFO] Ed448 batch size: %d (AVX512=8, AVX2=4, CPU=1)\n", bs);

    printf("\n%s\n", all ? "ALL ED448 BATCH TESTS PASSED" : "SOME ED448 BATCH TESTS FAILED");
    return all ? 0 : 1;
}
