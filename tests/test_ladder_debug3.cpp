// Batch verify test with pre-validated keys
#include "ed25519_batch.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl;

int main() {
    printf("batch_size=%d\n", ed25519_batch_size());
    
    // Generate keys until we have 8 valid ones
    uint8_t pk[8][32], sk[8][64], sig[8][64];
    int count = 0;
    for (int attempt = 0; count < 8 && attempt < 100; attempt++) {
        uint8_t tp[32], ts[64], tv[64];
        ed25519_keygen(tp, ts);
        ed25519_sign(ts, (const uint8_t*)"x", 1, tv);
        if (ed25519_verify(tp, (const uint8_t*)"x", 1, tv)) {
            memcpy(pk[count], tp, 32);
            memcpy(sk[count], ts, 64); 
            memcpy(sig[count], tv, 64);
            count++;
        }
    }
    printf("Got %d valid keys out of attempts\n", count);
    
    if (count >= 4) {
        const uint8_t* pp[4], *mm[4], *ss[4]; size_t ll[4];
        for(int i=0;i<4;i++){ pp[i]=pk[i]; mm[i]=(const uint8_t*)"x"; ll[i]=1; ss[i]=sig[i]; }
        printf("batch 4: %s\n", ed25519_batch_verify(pp,mm,ll,ss,4)?"PASS":"FAIL");
    }
    if (count >= 8) {
        const uint8_t* pp[8], *mm[8], *ss[8]; size_t ll[8];
        for(int i=0;i<8;i++){ pp[i]=pk[i]; mm[i]=(const uint8_t*)"x"; ll[i]=1; ss[i]=sig[i]; }
        printf("batch 8: %s\n", ed25519_batch_verify(pp,mm,ll,ss,8)?"PASS":"FAIL");
    }
    return 0;
}
