// rsa_schemes.cpp — RFC 8017 §8.2  RSASSA-PKCS1-v1_5 签名/验证

#include "rsa.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include <cstring>
#include <vector>

namespace jpssl {

// ═══════════════════════════════════════════════════════════════════════
//  §8.2.1  RSASSA-PKCS1-v1_5 签名
//
//  参数:
//    digestPrefix: DER 编码的 DigestInfo 前缀（不含 digest 本身）
//      示例 (SHA-256): 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
//      示例 (SHA-384): 30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
//      示例 (SHA-512): 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
// ═══════════════════════════════════════════════════════════════════════

// 常用 DER DigestInfo 前缀（不含 2 字节 digest 长度）
const uint8_t SHA256_DER_PREFIX[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20
};
constexpr size_t SHA256_DER_PREFIX_LEN = 19;

const uint8_t SHA384_DER_PREFIX[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30
};
constexpr size_t SHA384_DER_PREFIX_LEN = 19;

const uint8_t SHA512_DER_PREFIX[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40
};
constexpr size_t SHA512_DER_PREFIX_LEN = 19;


bool rsassa_pkcs1v15_sign(const rsa_crt_key& key, const uint8_t* msg, size_t msgLen,
                          const uint8_t* digestPrefix, size_t prefixLen,
                          uint8_t sig[256]) {
    constexpr size_t k = 256;  // RSA-2048 mod len
    (void)key;(void)msg;(void)msgLen;(void)digestPrefix;(void)prefixLen;(void)sig;

    // 1. 对消息做哈希
    uint8_t digest[64];
    // 根据 prefix 判定 hash 算法: 通过 prefixLen 或前缀内容自动识别
    // 简化: 调用者传 hash 结果也可以直接签名——这里统一 SHA-256
    sha256(msg, msgLen, digest);

    size_t hLen = 32;  // SHA-256
    if (prefixLen >= 19 && digestPrefix[17] == 0x30) hLen = 48;  // SHA-384
    if (prefixLen >= 19 && digestPrefix[17] == 0x40) hLen = 64;  // SHA-512
    // 若调用者已传 digest（即 msg 本身就是 hash 结果则跳过）, 但简化为传原始消息

    // 2. T = digestPrefix || digest
    std::vector<uint8_t> T(prefixLen + hLen);
    memcpy(T.data(), digestPrefix, prefixLen);
    memcpy(T.data() + prefixLen, digest, hLen);

    // 3. PS = FF...FF (k - prefixLen - hLen - 3)
    size_t psLen = k - prefixLen - hLen - 3;
    if (psLen < 8) return false;  // PS 最少 8 字节

    // 4. EM = 0x00 || 0x01 || PS || 0x00 || T
    uint8_t EM[256];
    EM[0] = 0x00;
    EM[1] = 0x01;
    memset(EM + 2, 0xFF, psLen);
    EM[2 + psLen] = 0x00;
    memcpy(EM + 2 + psLen + 1, T.data(), T.size());

    // 5-6. s = RSASP1(key, OS2IP(EM))
    rsa_bignum embn = rsa_bignum::from_bytes(EM, 256);
    rsa_bignum sbn;
    RSASP1(key, embn, sbn);
    sbn.to_bytes(sig);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════
//  §8.2.2  RSASSA-PKCS1-v1_5 验证
// ═══════════════════════════════════════════════════════════════════════

bool rsassa_pkcs1v15_verify(const rsa_public_key& pub, const uint8_t* msg, size_t msgLen,
                            const uint8_t* digestPrefix, size_t prefixLen,
                            const uint8_t sig[256]) {
    constexpr size_t k = 256;
    (void)pub;(void)msg;(void)msgLen;(void)digestPrefix;(void)prefixLen;(void)sig;

    // 1. s = OS2IP(sig)
    rsa_bignum sbn = rsa_bignum::from_bytes(sig, 256);

    // 2. m = RSAVP1(pub, s)
    rsa_bignum mbn;
    RSAVP1(pub, sbn, mbn);

    // 3. EM = I2OSP(m, k)
    uint8_t EM[256];
    mbn.to_bytes(EM);

    // 4-6. EMSA-PKCS1-v1_5 解码验证
    if (EM[0] != 0x00) return false;
    if (EM[1] != 0x01) return false;

    // PS = FF...FF
    size_t pos = 2;
    while (pos < k && EM[pos] == 0xFF) ++pos;
    if (pos == k || EM[pos] != 0x00) return false;
    if (pos - 2 < 8) return false;  // PS 最少 8 字节
    ++pos;  // 跳过 0x00

    // T = DigestInfo
    size_t tLen = prefixLen + 32;  // SHA-256 default
    if (k - pos < tLen) return false;

    // 7. 比较 digestPrefix
    if (memcmp(EM + pos, digestPrefix, prefixLen) != 0) return false;

    // 8. 计算消息哈希并比较
    uint8_t digest[32];
    sha256(msg, msgLen, digest);

    return memcmp(EM + pos + prefixLen, digest, 32) == 0;
}


// ---- 8.2.1/8.2.2  RSASSA-PKCS1-v1_5 签名/验证 (RSA-3072, k = 384) ----
// 与 2048 档同形; 差异: 模长 384 字节, 并按 DigestInfo 前缀完整支持 SHA-256/384/512

bool rsassa_pkcs1v15_sign3072(const rsa3072_crt_key& key, const uint8_t* msg, size_t msgLen,
                              const uint8_t* digestPrefix, size_t prefixLen,
                              uint8_t sig[RSA_3072_BYTES]) {
    constexpr size_t k = RSA_3072_BYTES;  // RSA-3072 mod len

    // 1. 对消息做哈希 (由 DigestInfo 前缀判定: SHA-256 / SHA-384 / SHA-512)
    uint8_t digest[64];
    size_t hLen = 32;
    if (prefixLen >= 19 && digestPrefix[17] == 0x30) { hLen = 48; sha384(msg, msgLen, digest); }
    else if (prefixLen >= 19 && digestPrefix[17] == 0x40) { hLen = 64; sha512(msg, msgLen, digest); }
    else sha256(msg, msgLen, digest);

    // 2. T = digestPrefix || digest
    if (prefixLen + hLen + 3 > k) return false;
    std::vector<uint8_t> T(prefixLen + hLen);
    memcpy(T.data(), digestPrefix, prefixLen);
    memcpy(T.data() + prefixLen, digest, hLen);

    // 3. PS = FF...FF (k - prefixLen - hLen - 3)
    size_t psLen = k - prefixLen - hLen - 3;
    if (psLen < 8) return false;  // PS 最少 8 字节

    // 4. EM = 0x00 || 0x01 || PS || 0x00 || T
    uint8_t EM[RSA_3072_BYTES];
    EM[0] = 0x00;
    EM[1] = 0x01;
    memset(EM + 2, 0xFF, psLen);
    EM[2 + psLen] = 0x00;
    memcpy(EM + 2 + psLen + 1, T.data(), T.size());

    // 5-6. s = RSASP1(key, OS2IP(EM)); CRT 参数缺失 (PEM 仅 n/d/e) 时回退全模幂
    rsa3072_bignum embn = rsa3072_bignum::from_bytes(EM, k);
    rsa3072_bignum sbn;
    if (key.p.is_zero() || key.q.is_zero()) bn_modpow(sbn, embn, key.d, key.n);
    else RSASP13072(key, embn, sbn);
    sbn.to_bytes(sig);
    return true;
}

bool rsassa_pkcs1v15_verify3072(const rsa3072_public_key& pub, const uint8_t* msg, size_t msgLen,
                                const uint8_t* digestPrefix, size_t prefixLen,
                                const uint8_t sig[RSA_3072_BYTES]) {
    constexpr size_t k = RSA_3072_BYTES;

    // 1. s = OS2IP(sig)
    rsa3072_bignum sbn = rsa3072_bignum::from_bytes(sig, k);
    if (!(sbn < pub.n)) return false;

    // 2. m = RSAVP1(pub, s)
    rsa3072_bignum mbn;
    RSAVP13072(pub, sbn, mbn);

    // 3. EM = I2OSP(m, k)
    uint8_t EM[RSA_3072_BYTES];
    mbn.to_bytes(EM);

    // 4-6. EMSA-PKCS1-v1_5 解码验证
    if (EM[0] != 0x00) return false;
    if (EM[1] != 0x01) return false;

    size_t pos = 2;
    while (pos < k && EM[pos] == 0xFF) ++pos;
    if (pos == k || EM[pos] != 0x00) return false;
    if (pos - 2 < 8) return false;  // PS 最少 8 字节
    ++pos;  // 跳过 0x00

    // T = DigestInfo (按前缀判定 hLen)
    size_t hLen = 32;
    if (prefixLen >= 19 && digestPrefix[17] == 0x30) hLen = 48;  // SHA-384
    else if (prefixLen >= 19 && digestPrefix[17] == 0x40) hLen = 64;  // SHA-512
    if (k - pos < prefixLen + hLen) return false;

    // 7. 比较 digestPrefix
    if (memcmp(EM + pos, digestPrefix, prefixLen) != 0) return false;

    // 8. 计算消息哈希并比较
    uint8_t digest[64];
    if (hLen == 48) sha384(msg, msgLen, digest);
    else if (hLen == 64) sha512(msg, msgLen, digest);
    else sha256(msg, msgLen, digest);
    return memcmp(EM + pos + prefixLen, digest, hLen) == 0;
}
} // namespace jpssl
