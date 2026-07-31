// rsa_schemes.cpp — RFC 8017 §8.2  RSASSA-PKCS1-v1_5 签名/验证

#include "rsa.hpp"
#include "sha256.hpp"
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

} // namespace jpssl
