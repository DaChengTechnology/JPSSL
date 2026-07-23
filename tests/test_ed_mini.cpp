#include "ed25519_batch.hpp"
#include <cstdio>
using namespace jpssl;
int main() {
    printf("batch_size=%d\n", ed25519_batch_size());
    
    // Single keygen+sign+verify
    uint8_t pk[32], sk[64], sig[64];
    ed25519_keygen(pk, sk);
    ed25519_sign(sk, (const uint8_t*)"x", 1, sig);
    printf("single verify: %s\n", ed25519_verify(pk, (const uint8_t*)"x", 1, sig)?"PASS":"FAIL");
    
    // Batch of 1
    const uint8_t* p = pk;
    const uint8_t* m = (const uint8_t*)"x";
    size_t l = 1;
    const uint8_t* s = sig;
    printf("batch 1: %s\n", ed25519_batch_verify(&p, &m, &l, &s, 1)?"PASS":"FAIL");
    
    // Batch of 5
    uint8_t p5[5][32], k5[5][64], v5[5][64];
    const uint8_t* pp[5], *mp[5], *sp[5];
    size_t lp[5];
    for(int i=0;i<5;i++){
        ed25519_keygen(p5[i], k5[i]);
        ed25519_sign(k5[i], (const uint8_t*)"x", 1, v5[i]);
        pp[i]=p5[i]; mp[i]=(const uint8_t*)"x"; lp[i]=1; sp[i]=v5[i];
    }
    printf("batch 5: %s\n", ed25519_batch_verify(pp, mp, lp, sp, 5)?"PASS":"FAIL");
    return 0;
}
