// rsa_pss.cpp - RFC 8017 搂8.1  RSASSA-PSS 签名/验证
//   支持 RSA-2048 / RSA-4096, SHA-256 / SHA-384 / SHA-512,
//   saltLen 默认 = hLen (RFC 8446 / TLS 1.3 CertificateVerify 要求)

#include "rsa.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "rand_os.hpp"
#include <cstring>
#include <vector>

namespace jpssl {

static size_t pss_hash_len(PssHash h) {
    switch (h) {
        case PssHash::SHA256: return 32;
        case PssHash::SHA384: return 48;
        case PssHash::SHA512: return 64;
    }
    return 0;
}

static bool pss_hash(PssHash h, const uint8_t* data, size_t len, uint8_t* out) {
    switch (h) {
        case PssHash::SHA256: sha256(data, len, out); return true;
        case PssHash::SHA384: sha384(data, len, out); return true;
        case PssHash::SHA512: sha512(data, len, out); return true;
    }
    return false;
}

static bool pss_mgf1(PssHash h, const uint8_t* seed, size_t seedLen,
                     uint8_t* mask, size_t maskLen) {
    switch (h) {
        case PssHash::SHA256: mgf1_sha256(seed, seedLen, mask, maskLen); return true;
        case PssHash::SHA384: mgf1_sha384(seed, seedLen, mask, maskLen); return true;
        case PssHash::SHA512: mgf1_sha512(seed, seedLen, mask, maskLen); return true;
    }
    return false;
}

// EMSA-PSS 编码 (RFC 8017 搂9.1.1), EM 长度 emLen, emBits = modBits - 1
static bool emsa_pss_encode(const uint8_t* mHash, size_t hLen, size_t emBits,
                            size_t sLen, PssHash hash, uint8_t* EM, size_t emLen) {
    if (hLen == 0 || hLen > 64 || sLen == 0 || sLen > 64) return false;
    if (emLen < hLen + sLen + 2) return false;
    size_t clearBits = 8 * emLen - emBits;
    if (clearBits >= 8) return false;

    // 2. 随机 salt (CSPRNG)
    uint8_t salt[64];
    if (!os_rand_bytes(salt, sLen)) return false;

    // 4. M' = 00..00(8) || mHash || salt
    uint8_t M_prime[8 + 64 + 64];
    memset(M_prime, 0, 8);
    memcpy(M_prime + 8, mHash, hLen);
    memcpy(M_prime + 8 + hLen, salt, sLen);

    // 5. H = Hash(M')
    uint8_t H[64];
    if (!pss_hash(hash, M_prime, 8 + hLen + sLen, H)) return false;

    // 6-7. DB = PS || 0x01 || salt
    size_t dbLen = emLen - hLen - 1;
    std::vector<uint8_t> DB(dbLen, 0);
    size_t psLen = emLen - sLen - hLen - 2;
    DB[psLen] = 0x01;
    memcpy(DB.data() + psLen + 1, salt, sLen);

    // 8-9. maskedDB = DB ^ MGF1(H, emLen - hLen - 1)
    std::vector<uint8_t> dbMask(dbLen);
    if (!pss_mgf1(hash, H, hLen, dbMask.data(), dbMask.size())) return false;
    for (size_t i = 0; i < dbLen; ++i) DB[i] ^= dbMask[i];

    // 10. 清空最高 8*emLen - emBits 位
    uint8_t topMask = (uint8_t)(0xFFu >> clearBits);
    DB[0] &= topMask;

    // 11. EM = maskedDB || H || 0xBC
    memcpy(EM, DB.data(), dbLen);
    memcpy(EM + dbLen, H, hLen);
    EM[emLen - 1] = 0xBC;
    return true;
}

// EMSA-PSS 验证 (RFC 8017 搂9.1.2)
static bool emsa_pss_verify(const uint8_t* mHash, size_t hLen, size_t emBits,
                            size_t sLen, PssHash hash,
                            const uint8_t* EM, size_t emLen) {
    if (hLen == 0 || hLen > 64 || sLen == 0 || sLen > 64) return false;
    if (emLen < hLen + sLen + 2) return false;
    size_t clearBits = 8 * emLen - emBits;
    if (clearBits >= 8) return false;

    // 6. 末字节必须为 0xBC
    if (EM[emLen - 1] != 0xBC) return false;

    size_t dbLen = emLen - hLen - 1;
    const uint8_t* maskedDB = EM;
    const uint8_t* H = EM + dbLen;

    // 7. maskedDB 最高 8*emLen - emBits 位必须为 0
    uint8_t topMask = (uint8_t)(0xFFu >> clearBits);
    if (maskedDB[0] & (uint8_t)~topMask) return false;

    // 8-9. DB = maskedDB ^ MGF1(H)
    std::vector<uint8_t> dbMask(dbLen);
    if (!pss_mgf1(hash, H, hLen, dbMask.data(), dbMask.size())) return false;
    std::vector<uint8_t> DB(dbLen);
    for (size_t i = 0; i < dbLen; ++i) DB[i] = (uint8_t)(maskedDB[i] ^ dbMask[i]);

    // 10. 清空 DB 最高位后再检查 PS
    DB[0] &= topMask;
    size_t psLen = emLen - sLen - hLen - 2;
    for (size_t i = 0; i < psLen; ++i)
        if (DB[i] != 0) return false;
    if (DB[psLen] != 0x01) return false;

    // 11-12. 重新计算 H' = Hash(00..00 || mHash || salt) 并比较
    uint8_t M_prime[8 + 64 + 64];
    memset(M_prime, 0, 8);
    memcpy(M_prime + 8, mHash, hLen);
    memcpy(M_prime + 8 + hLen, DB.data() + psLen + 1, sLen);
    uint8_t H2[64];
    if (!pss_hash(hash, M_prime, 8 + hLen + sLen, H2)) return false;
    return memcmp(H, H2, hLen) == 0;
}

// 鈺愨晲鈺?搂8.1.1  RSASSA-PSS 签名 (RSA-2048) 鈺愨晲鈺?

bool rsassa_pss_sign(const rsa_crt_key& key, const uint8_t* msg, size_t msgLen,
                     uint8_t sig[256], size_t saltLen, PssHash hash) {
    size_t hLen = pss_hash_len(hash);
    if (hLen == 0) return false;
    if (saltLen == 0) saltLen = hLen;
    uint8_t mHash[64];
    if (!pss_hash(hash, msg, msgLen, mHash)) return false;
    uint8_t EM[256];
    if (!emsa_pss_encode(mHash, hLen, 2047, saltLen, hash, EM, 256)) return false;

    // 12-13. s = RSASP1(key, OS2IP(EM))
    rsa_bignum embn = rsa_bignum::from_bytes(EM, 256);
    rsa_bignum sbn;
    if (key.p.is_zero() || key.q.is_zero()) {
        // CRT 参数缺失（PEM 导入的私钥仅含 n/d/e）：回退全模幂 s = EM^d mod n
        // （与 rsa_decrypt 的 CRT 缺失回退逻辑一致）
        bn_modpow(sbn, embn, key.d, key.n);
    } else {
        RSASP1(key, embn, sbn);
    }
    sbn.to_bytes(sig);
    return true;
}

// 鈺愨晲鈺?搂8.1.2  RSASSA-PSS 验证 (RSA-2048) 鈺愨晲鈺?

bool rsassa_pss_verify(const rsa_public_key& pub, const uint8_t* msg, size_t msgLen,
                       const uint8_t sig[256], size_t saltLen, PssHash hash) {
    size_t hLen = pss_hash_len(hash);
    if (hLen == 0) return false;
    if (saltLen == 0) saltLen = hLen;

    // 1-3. s = OS2IP(sig), 要求 s < n
    rsa_bignum sbn = rsa_bignum::from_bytes(sig, 256);
    if (!(sbn < pub.n)) return false;

    // 4. m = RSAVP1(pub, s)
    rsa_bignum mbn;
    RSAVP1(pub, sbn, mbn);

    // 5. EM = I2OSP(m, emLen)
    uint8_t EM[256];
    mbn.to_bytes(EM);

    uint8_t mHash[64];
    if (!pss_hash(hash, msg, msgLen, mHash)) return false;
    return emsa_pss_verify(mHash, hLen, 2047, saltLen, hash, EM, 256);
}

// 鈺愨晲鈺?搂8.1.1  RSASSA-PSS 签名 (RSA-4096) 鈺愨晲鈺?

bool rsassa_pss_sign4096(const rsa4096_crt_key& key, const uint8_t* msg, size_t msgLen,
                         uint8_t sig[512], size_t saltLen, PssHash hash) {
    size_t hLen = pss_hash_len(hash);
    if (hLen == 0) return false;
    if (saltLen == 0) saltLen = hLen;
    uint8_t mHash[64];
    if (!pss_hash(hash, msg, msgLen, mHash)) return false;
    uint8_t EM[512];
    if (!emsa_pss_encode(mHash, hLen, 4095, saltLen, hash, EM, 512)) return false;

    rsa4096_bignum embn = rsa4096_bignum::from_bytes(EM, 512);
    rsa4096_bignum sbn;
    RSASP14096(key, embn, sbn);
    sbn.to_bytes(sig);
    return true;
}

// 鈺愨晲鈺?搂8.1.2  RSASSA-PSS 验证 (RSA-4096) 鈺愨晲鈺?

bool rsassa_pss_verify4096(const rsa4096_public_key& pub, const uint8_t* msg, size_t msgLen,
                           const uint8_t sig[512], size_t saltLen, PssHash hash) {
    size_t hLen = pss_hash_len(hash);
    if (hLen == 0) return false;
    if (saltLen == 0) saltLen = hLen;

    rsa4096_bignum sbn = rsa4096_bignum::from_bytes(sig, 512);
    if (!(sbn < pub.n)) return false;

    rsa4096_bignum mbn;
    RSAVP14096(pub, sbn, mbn);

    uint8_t EM[512];
    mbn.to_bytes(EM);

    uint8_t mHash[64];
    if (!pss_hash(hash, msg, msgLen, mHash)) return false;
    return emsa_pss_verify(mHash, hLen, 4095, saltLen, hash, EM, 512);
}

} // namespace jpssl
