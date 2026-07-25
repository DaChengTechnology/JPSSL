#include "aes.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <span>
using namespace jpssl;

int main() {
    uint8_t key[16] = {0xf9,0x28,0x7d,0xc1,0x8b,0x4c,0x81,0x67,0x3a,0xf0,0xb4,0x8d,0xe6,0xde,0x87,0x75};
    uint8_t iv[12]  = {0x90,0x15,0x5e,0xae,0x7b,0x2e,0x7e,0xac,0x45,0x5c,0x90,0xc2};

    const char* plaintext = "Hello GCM test!";
    size_t pt_len = strlen(plaintext);

    aes_context ctx;
    ctx.init(std::span<const uint8_t,16>(key, 16));

    std::vector<uint8_t> ct;
    uint8_t tag[16];
    aes_gcm_encrypt(ctx, iv, 12,
                    std::span<const uint8_t>((const uint8_t*)plaintext, pt_len),
                    std::span<const uint8_t>(),
                    ct, tag, 16);

    printf("Encrypted %zu bytes, tag: ", pt_len);
    for (int i = 0; i < 16; i++) printf("%02x", tag[i]);
    printf("\n");

    // 解密
    std::vector<uint8_t> pt_out;
    bool ok = aes_gcm_decrypt(ctx, iv, 12,
                              std::span<const uint8_t>(ct.data(), ct.size()),
                              std::span<const uint8_t>(),
                              tag, 16, pt_out);
    printf("Decrypt ok=%d, size=%zu\n", ok, pt_out.size());
    if (ok) {
        pt_out.push_back(0);
        printf("Plaintext: %s\n", pt_out.data());
    }

    // 测试 TLS 1.3 格式的 inner data
    // inner = HANDSHAKE(22) + data + HANDSHAKE(22)
    std::vector<uint8_t> inner;
    inner.push_back(22); // HANDSHAKE
    const char* hs_data = "test handshake message";
    inner.insert(inner.end(), (const uint8_t*)hs_data, (const uint8_t*)hs_data + strlen(hs_data));
    inner.push_back(22); // HANDSHAKE

    std::vector<uint8_t> ct2;
    uint8_t tag2[16];
    aes_gcm_encrypt(ctx, iv, 12,
                    std::span<const uint8_t>(inner.data(), inner.size()),
                    std::span<const uint8_t>(),
                    ct2, tag2, 16);

    std::vector<uint8_t> inner_out;
    bool ok2 = aes_gcm_decrypt(ctx, iv, 12,
                               std::span<const uint8_t>(ct2.data(), ct2.size()),
                               std::span<const uint8_t>(),
                               tag2, 16, inner_out);
    printf("Inner decrypt ok=%d, size=%zu\n", ok2, inner_out.size());
    if (ok2) {
        printf("Inner[0]=%d, Inner.back()=%d\n", inner_out[0], inner_out.back());
    }
    return 0;
}
