// rsa_pss.cpp — RFC 8017 §8.1  RSASSA-PSS 签名/验证方案
//   默认 SHA-256, saltLen=32

#include "rsa.hpp"
#include "sha256.hpp"
#include <algorithm>
#include <cstring>
#include <random>
#include <vector>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  §8.1.1  RSASSA-PSS 签名
//
//  Options:
//    Hash       SHA-256 (hLen=32)
//    MGF        MGF1-SHA-256
//    saltLen    默认 32 (匹配 hLen)
//    emBits     2048 - 1 = 2047 (modBits - 1)
// ═══════════════════════════════════════════════════════════════════════

bool rsassa_pss_sign(const rsa_crt_key& key, const uint8_t* msg, size_t msgLen,
                     uint8_t sig[256], size_t saltLen) {
    constexpr size_t k = 256;       // RSA-2048 模数长度
    constexpr size_t hLen = 32;     // SHA-256
    constexpr size_t emBits = 2047; // modBits - 1

    // 1. mHash = Hash(M)
    uint8_t mHash[32];
    sha256(msg, msgLen, mHash);

    // 2. emLen = ceil(emBits/8) = 256
    size_t emLen = k;
    if (emLen < hLen + saltLen + 2) return false;

    // 3. 随机 salt
    uint8_t salt[32] = {};
    if (saltLen > 0) {
        std::mt19937_64 rng(std::random_device{}());
        for (size_t i = 0; i < saltLen; i += 8) {
            uint64_t v = rng();
            for (size_t j = 0; j < 8 && i + j < saltLen; ++j)
                salt[i + j] = (uint8_t)(v >> (j * 8));
        }
    }

    // 4. M' = 00 00 00 00 00 00 00 00 || mHash || salt
    uint8_t M_prime[8 + 32 + 32];
    memset(M_prime, 0, 8);
    memcpy(M_prime + 8, mHash, 32);
    memcpy(M_prime + 40, salt, saltLen);

    // 5. H = Hash(M')
    uint8_t H[32];
    sha256(M_prime, 8 + 32 + saltLen, H);

    // 6. PS = 00..00 (emLen - saltLen - hLen - 2)
    size_t psLen = emLen - saltLen - hLen - 2;

    // 7. DB = PS || 01 || salt
    std::vector<uint8_t> DB(emLen - hLen - 1, 0);
    DB[psLen] = 0x01;
    memcpy(DB.data() + psLen + 1, salt, saltLen);

    // 8. dbMask = MGF1(H, emLen - hLen - 1)
    uint8_t dbMask[256 - 32 - 1];
    mgf1_sha256(H, 32, dbMask, sizeof(dbMask));

    // 9. maskedDB = DB ^ dbMask
    for (size_t i = 0; i < sizeof(dbMask); ++i) DB[i] ^= dbMask[i];

    // 10. 将 maskedDB 最高 8*emLen - emBits 位清零
    //     emBits = 2047, 8*256 - 2047 = 1 → 最高 1 bit 清零
    DB[0] &= 0x7F;

    // 11. EM = maskedDB || H || 0xBC
    uint8_t EM[256];
    memcpy(EM, DB.data(), sizeof(dbMask));
    memcpy(EM + sizeof(dbMask), H, 32);
    EM[255] = 0xBC;

    // 12-13. s = RSASP1(key, OS2IP(EM))
    rsa_bignum embn = rsa_bignum::from_bytes(EM, 256);
    rsa_bignum sbn;
    RSASP1(key, embn, sbn);
    sbn.to_bytes(sig);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  §8.1.2  RSASSA-PSS 验证
// ═══════════════════════════════════════════════════════════════════════

bool rsassa_pss_verify(const rsa_public_key& pub, const uint8_t* msg, size_t msgLen,
                       const uint8_t sig[256], size_t saltLen) {
    constexpr size_t k = 256;
    constexpr size_t hLen = 32;
    constexpr size_t emBits = 2047;

    // 1-3. 长度检查 + s = OS2IP
    rsa_bignum sbn = rsa_bignum::from_bytes(sig, 256);
    if (sbn.bit_length() > emBits + 1) return false; // s >= n — 实际上检查 bit_length <= 2048

    // 4. m = RSAVP1(pub, s)
    rsa_bignum mbn;
    RSAVP1(pub, sbn, mbn);

    // 5. EM = I2OSP(m, emLen)
    uint8_t EM[256];
    mbn.to_bytes(EM);
    size_t emLen = k;

    // 6-12. EMSA-PSS 验证
    if (EM[emLen - 1] != 0xBC) return false;

    uint8_t maskedDB[256 - 32 - 1];
    memcpy(maskedDB, EM, sizeof(maskedDB));

    uint8_t H[32];
    memcpy(H, EM + sizeof(maskedDB), 32);

    // 检查最高位
    if (EM[0] & 0x80) return false;

    uint8_t dbMask[256 - 32 - 1];
    mgf1_sha256(H, 32, dbMask, sizeof(dbMask));

    uint8_t DB[256 - 32 - 1];
    for (size_t i = 0; i < sizeof(DB); ++i) DB[i] = maskedDB[i] ^ dbMask[i];

    DB[0] &= 0x7F;

    // PS 检查
    size_t psLen = emLen - saltLen - hLen - 2;
    for (size_t i = 0; i < psLen; ++i)
        if (DB[i] != 0) return false;
    if (DB[psLen] != 0x01) return false;

    uint8_t salt[32];
    memcpy(salt, DB + psLen + 1, saltLen);

    // 7-8. mHash' = Hash(M)
    uint8_t mHash[32];
    sha256(msg, msgLen, mHash);

    // 9. M' = 00||...||mHash||salt
    uint8_t M_prime[8 + 32 + 32];
    memset(M_prime, 0, 8);
    memcpy(M_prime + 8, mHash, 32);
    memcpy(M_prime + 40, salt, saltLen);

    uint8_t H2[32];
    sha256(M_prime, 8 + 32 + saltLen, H2);

    // 10. H == H2
    return memcmp(H, H2, 32) == 0;
}

} // namespace jpssl
