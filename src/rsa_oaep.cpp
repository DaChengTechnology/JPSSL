// rsa_oaep.cpp — RFC 8017 §7.1  RSAES-OAEP 加密/解密方案
//   支持 SHA-256 (默认), 可扩展至 SHA-384/SHA-512

#include "rsa.hpp"
#include "sha256.hpp"
#include <cstring>
#include <random>
#include <vector>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  §7.1.1  RSAES-OAEP 加密
//
//  Options:
//    Hash       SHA-256 (hLen=32)
//    MGF        MGF1-SHA-256
//    Label      label + labelLen (可为空串, label=nullptr 表示空)
//    Input      msg (长度 ≤ k − 2hLen − 2)
//    Output     ct[k] = 密文 (256 字节 for 2048-bit)
// ═══════════════════════════════════════════════════════════════════════

bool rsaes_oaep_encrypt(const rsa_public_key& pub, std::span<const uint8_t> msg,
                        const uint8_t* label, size_t labelLen,
                        uint8_t ct[256]) {
    (void)pub;(void)msg;(void)label;(void)labelLen;(void)ct;
    constexpr size_t k = 256;    // RSA-2048 mod len
    constexpr size_t hLen = 32;  // SHA-256

    // 0. 长度检查
    size_t mLen = msg.size();
    if (mLen > k - 2*hLen - 2) return false;
    if (!label) { label = (const uint8_t*)""; labelLen = 0; }

    // 1. lHash = Hash(L)
    uint8_t lHash[32];
    sha256(label, labelLen, lHash);

    // 2. PS = 00...00 (k - mLen - 2*hLen - 2 字节)
    size_t psLen = k - mLen - 2*hLen - 2;

    // 3. DB = lHash || PS || 01 || msg
    std::vector<uint8_t> DB(hLen + psLen + 1 + mLen);
    memcpy(DB.data(), lHash, hLen);
    memset(DB.data() + hLen, 0, psLen);
    DB[hLen + psLen] = 0x01;
    memcpy(DB.data() + hLen + psLen + 1, msg.data(), mLen);

    // 4. 随机 seed
    uint8_t seed[32];
    static std::mt19937_64 rng(std::random_device{}());
    for (int i = 0; i < 8; ++i) {
        uint64_t v = rng();
        seed[i*8+0] = (uint8_t)(v);        seed[i*8+1] = (uint8_t)(v>>8);
        seed[i*8+2] = (uint8_t)(v>>16);     seed[i*8+3] = (uint8_t)(v>>24);
        seed[i*8+4] = (uint8_t)(v>>32);     seed[i*8+5] = (uint8_t)(v>>40);
        seed[i*8+6] = (uint8_t)(v>>48);     seed[i*8+7] = (uint8_t)(v>>56);
    }

    // 5. dbMask = MGF1(seed, k - hLen - 1)
    uint8_t dbMask[256 - 32 - 1];
    mgf1_sha256(seed, 32, dbMask, sizeof(dbMask));

    // 6. maskedDB = DB ^ dbMask
    for (size_t i = 0; i < sizeof(dbMask); ++i) DB[i] ^= dbMask[i];

    // 7. seedMask = MGF1(maskedDB, hLen)
    uint8_t seedMask[32];
    mgf1_sha256(DB.data(), sizeof(dbMask), seedMask, 32);

    // 8. maskedSeed = seed ^ seedMask
    uint8_t maskedSeed[32];
    for (int i = 0; i < 32; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

    // 9. EM = 0x00 || maskedSeed || maskedDB
    uint8_t EM[256] = {};
    memcpy(EM + 1, maskedSeed, 32);
    memcpy(EM + 1 + 32, DB.data(), sizeof(dbMask));

    // 10. m = OS2IP(EM)
    rsa_bignum m = rsa_bignum::from_bytes(EM, 256);

    // 11. c = RSAEP(pub, m)
    rsa_bignum cbn;
    RSAEP(pub, m, cbn);

    // 12. C = I2OSP(c, k)
    cbn.to_bytes(ct);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  §7.1.2  RSAES-OAEP 解密
// ═══════════════════════════════════════════════════════════════════════

bool rsaes_oaep_decrypt(const rsa_crt_key& key, const uint8_t ct[256],
                        const uint8_t* label, size_t labelLen,
                        std::vector<uint8_t>& msg) {
    (void)key;(void)ct;(void)label;(void)labelLen;(void)msg;
    constexpr size_t k = 256;
    constexpr size_t hLen = 32;
    if (!label) { label = (const uint8_t*)""; labelLen = 0; }

    // 1. 长度检查: 密文必须 = k 字节
    // (外层已保证)

    // 2. c = OS2IP(ct)
    rsa_bignum c = rsa_bignum::from_bytes(ct, 256);
    if (c.bit_length() > 2048) return false;  // c ≥ n

    // 3. m = RSADP(key, c)
    rsa_bignum m;
    RSADP(key, c, m);

    // 4. EM = I2OSP(m, k)
    uint8_t EM[256];
    m.to_bytes(EM);

    // 5. lHash' = Hash(L)
    uint8_t lHash[32];
    sha256(label, labelLen, lHash);

    // 6-12. EME-OAEP 解码
    uint8_t maskedSeed[32];
    memcpy(maskedSeed, EM + 1, 32);

    uint8_t maskedDB[256 - 32 - 1];
    memcpy(maskedDB, EM + 1 + 32, sizeof(maskedDB));

    uint8_t seedMask[32];
    mgf1_sha256(maskedDB, sizeof(maskedDB), seedMask, 32);

    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    uint8_t dbMask[256 - 32 - 1];
    mgf1_sha256(seed, 32, dbMask, sizeof(dbMask));

    uint8_t DB[256 - 32 - 1];
    for (size_t i = 0; i < sizeof(DB); ++i) DB[i] = maskedDB[i] ^ dbMask[i];

    // 验证:
    //   - lHash' == DB[0..hLen-1]
    //   - PS 为全零直到 0x01
    if (memcmp(DB, lHash, hLen) != 0) return false;

    size_t pos = hLen;
    while (pos < sizeof(DB) && DB[pos] == 0x00) ++pos;
    if (pos >= sizeof(DB) || DB[pos] != 0x01) return false;
    ++pos;

    msg.assign(DB + pos, DB + sizeof(DB));
    return true;
}

} // namespace jpssl
