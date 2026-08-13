/*
 * jpssl.h — jpssl 密码学库的纯 C 桥接头（Swift 可导入）
 *
 * 通过 module.modulemap 暴露为 Clang 模块 `JPSslC`，Swift 侧 `import JPSslC`
 * 即可调用全部符号。所有函数均为 extern "C"，不包含任何 C++ 类型，
 * 因此也适用于纯 C 调用方。
 *
 * 约定：
 *   - 返回 `int` 的布尔函数：1 = 成功/真，0 = 失败/假；
 *   - 变长输出统一由库内 malloc 分配，调用方用 jp_free() 释放；
 *   - 流式上下文为不透明句柄（jp_*_ctx_new / jp_*_ctx_free）。
 *
 * 最低支持：iOS 13.0 / arm64（ARMv8）。
 */
#ifndef JPSSL_C_BRIDGE_H
#define JPSSL_C_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 释放桥接层 malloc 的缓冲区 */
void jp_free(void* p);

/* ═══════════════════════════════════════════════════════════════════
 *  随机数
 * ═══════════════════════════════════════════════════════════════════ */
int jp_secure_rand(uint8_t* out, size_t len);

/* ═══════════════════════════════════════════════════════════════════
 *  SHA-1 / SHA-256 / SHA-384 / SHA-512 / SHA3 / SHAKE / SM3
 *  —— 一次性 + 流式上下文
 * ═══════════════════════════════════════════════════════════════════ */
void jp_sha1(const uint8_t* data, size_t len, uint8_t out[20]);
typedef struct jp_sha1_ctx jp_sha1_ctx;
jp_sha1_ctx* jp_sha1_ctx_new(void);
void jp_sha1_update(jp_sha1_ctx* c, const uint8_t* data, size_t len);
void jp_sha1_final(jp_sha1_ctx* c, uint8_t out[20]);
void jp_sha1_ctx_free(jp_sha1_ctx* c);

void jp_sha256(const uint8_t* data, size_t len, uint8_t out[32]);
typedef struct jp_sha256_ctx jp_sha256_ctx;
jp_sha256_ctx* jp_sha256_ctx_new(void);
void jp_sha256_update(jp_sha256_ctx* c, const uint8_t* data, size_t len);
void jp_sha256_final(jp_sha256_ctx* c, uint8_t out[32]);
void jp_sha256_ctx_free(jp_sha256_ctx* c);

void jp_sha384(const uint8_t* data, size_t len, uint8_t out[48]);
void jp_sha512(const uint8_t* data, size_t len, uint8_t out[64]);
typedef struct jp_sha512_ctx jp_sha512_ctx;
jp_sha512_ctx* jp_sha512_ctx_new(int is384); /* 1 = SHA-384, 0 = SHA-512 */
void jp_sha512_update(jp_sha512_ctx* c, const uint8_t* data, size_t len);
void jp_sha512_final(jp_sha512_ctx* c, uint8_t* out); /* 48 (384) 或 64 字节 */
void jp_sha512_ctx_free(jp_sha512_ctx* c);

/* SHA3-256/384/512（一次性） */
void jp_sha3_256(const uint8_t* data, size_t len, uint8_t out[32]);
void jp_sha3_384(const uint8_t* data, size_t len, uint8_t out[48]);
void jp_sha3_512(const uint8_t* data, size_t len, uint8_t out[64]);
typedef struct jp_sha3_ctx jp_sha3_ctx;
jp_sha3_ctx* jp_sha3_ctx_new(int variant); /* 0=256 1=384 2=512 */
void jp_sha3_update(jp_sha3_ctx* c, const uint8_t* data, size_t len);
void jp_sha3_final(jp_sha3_ctx* c, uint8_t* out); /* 32/48/64 字节 */
void jp_sha3_ctx_free(jp_sha3_ctx* c);

/* SHAKE128 / SHAKE256 可扩展输出 */
void jp_shake128(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len);
void jp_shake256(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_len);
typedef struct jp_shake_ctx jp_shake_ctx;
jp_shake_ctx* jp_shake_ctx_new(int is256); /* 0 = SHAKE128, 1 = SHAKE256 */
void jp_shake_update(jp_shake_ctx* c, const uint8_t* data, size_t len);
void jp_shake_squeeze(jp_shake_ctx* c, uint8_t* out, size_t out_len);
void jp_shake_ctx_free(jp_shake_ctx* c);

/* SM3（国密杂凑，GM/T 0004） */
void jp_sm3(const uint8_t* data, size_t len, uint8_t out[32]);
typedef struct jp_sm3_ctx jp_sm3_ctx;
jp_sm3_ctx* jp_sm3_ctx_new(void);
void jp_sm3_update(jp_sm3_ctx* c, const uint8_t* data, size_t len);
void jp_sm3_final(jp_sm3_ctx* c, uint8_t out[32]);
void jp_sm3_ctx_free(jp_sm3_ctx* c);

/* ═══════════════════════════════════════════════════════════════════
 *  HMAC / HKDF
 * ═══════════════════════════════════════════════════════════════════ */
void jp_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t mac[32]);
void jp_hmac_sha384(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t mac[48]);
void jp_hmac_sm3(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t mac[32]);

void jp_hkdf_extract_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]);
void jp_hkdf_expand_sha256(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len);
void jp_hkdf_extract_sha384(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[48]);
void jp_hkdf_expand_sha384(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len);
void jp_hkdf_extract_sm3(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]);
void jp_hkdf_expand_sm3(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len);

/* ═══════════════════════════════════════════════════════════════════
 *  AES-128/192/256
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct jp_aes_ctx jp_aes_ctx;
jp_aes_ctx* jp_aes_init(const uint8_t* key, size_t key_len); /* 16/24/32 字节 */
void jp_aes_free(jp_aes_ctx* c);
void jp_aes_encrypt_block(jp_aes_ctx* c, const uint8_t in[16], uint8_t out[16]);
void jp_aes_decrypt_block(jp_aes_ctx* c, const uint8_t in[16], uint8_t out[16]);
/* ECB：len 必须是 16 的倍数 */
int jp_aes_ecb_encrypt(jp_aes_ctx* c, const uint8_t* in, uint8_t* out, size_t len);
int jp_aes_ecb_decrypt(jp_aes_ctx* c, const uint8_t* in, uint8_t* out, size_t len);
/* CBC + PKCS#7：*out 由库 malloc（长度 = 对齐到 16 的倍数） */
int jp_aes_cbc_encrypt(jp_aes_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                       uint8_t** out, size_t* out_len);
int jp_aes_cbc_decrypt(jp_aes_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                       uint8_t** out, size_t* out_len);
/* GCM AEAD：ct 与 pt 等长由调用方分配；tag 长度 >= tag_len */
int jp_aes_gcm_encrypt(jp_aes_ctx* c, const uint8_t* iv, size_t iv_len,
                       const uint8_t* pt, size_t pt_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* ct, uint8_t* tag, size_t tag_len);
int jp_aes_gcm_decrypt(jp_aes_ctx* c, const uint8_t* iv, size_t iv_len,
                       const uint8_t* ct, size_t ct_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* tag, size_t tag_len,
                       uint8_t* pt);
/* CCM AEAD：nonce 7-13 字节 */
int jp_aes_ccm_encrypt(jp_aes_ctx* c, const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* pt, size_t pt_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* ct, uint8_t* tag, size_t tag_len);
int jp_aes_ccm_decrypt(jp_aes_ctx* c, const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* ct, size_t ct_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* tag, size_t tag_len,
                       uint8_t* pt);
/* GHASH / GF(2^128) 原语 */
void jp_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]);
void jp_ghash(const uint8_t H[16], const uint8_t* data, size_t len, uint8_t out[16]);
void jp_gcm_ghash(const uint8_t H[16], const uint8_t* aad, size_t aad_len,
                  const uint8_t* data, size_t data_len, uint8_t out[16]);

/* ═══════════════════════════════════════════════════════════════════
 *  ChaCha20-Poly1305 (RFC 8439)
 * ═══════════════════════════════════════════════════════════════════ */
void jp_chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t keystream[64]);
void jp_chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                     const uint8_t* in, uint8_t* out, size_t len);
void jp_poly1305_mac(const uint8_t key[32], const uint8_t* msg, size_t msg_len, uint8_t tag[16]);
int jp_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t* pt, size_t pt_len,
                                 const uint8_t* aad, size_t aad_len,
                                 uint8_t* ct, uint8_t tag[16]);
int jp_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t* ct, size_t ct_len,
                                 const uint8_t* aad, size_t aad_len,
                                 const uint8_t tag[16], uint8_t* pt);

/* ═══════════════════════════════════════════════════════════════════
 *  SM4（国密分组，GM/T 0002）
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct jp_sm4_ctx jp_sm4_ctx;
jp_sm4_ctx* jp_sm4_init(const uint8_t key[16]);
void jp_sm4_free(jp_sm4_ctx* c);
void jp_sm4_encrypt_block(const jp_sm4_ctx* c, const uint8_t in[16], uint8_t out[16]);
void jp_sm4_decrypt_block(const jp_sm4_ctx* c, const uint8_t in[16], uint8_t out[16]);
int jp_sm4_cbc_encrypt(const jp_sm4_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                       uint8_t** out, size_t* out_len);
int jp_sm4_cbc_decrypt(const jp_sm4_ctx* c, const uint8_t iv[16], const uint8_t* in, size_t in_len,
                       uint8_t** out, size_t* out_len);
int jp_sm4_gcm_encrypt(const jp_sm4_ctx* c, const uint8_t* iv, size_t iv_len,
                       const uint8_t* pt, size_t pt_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* ct, uint8_t* tag, size_t tag_len);
int jp_sm4_gcm_decrypt(const jp_sm4_ctx* c, const uint8_t* iv, size_t iv_len,
                       const uint8_t* ct, size_t ct_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* tag, size_t tag_len, uint8_t* pt);
int jp_sm4_ccm_encrypt(const jp_sm4_ctx* c, const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* pt, size_t pt_len,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* ct, uint8_t* tag, size_t tag_len);
int jp_sm4_ccm_decrypt(const jp_sm4_ctx* c, const uint8_t* nonce, size_t nonce_len,
                       const uint8_t* ct, size_t ct_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* tag, size_t tag_len, uint8_t* pt);

/* ═══════════════════════════════════════════════════════════════════
 *  X25519 / X448 (RFC 7748)
 * ═══════════════════════════════════════════════════════════════════ */
void jp_x25519_generate_keypair(uint8_t pub[32], uint8_t priv[32]);
void jp_x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void jp_x448_generate_keypair(uint8_t pub[56], uint8_t priv[56]);
void jp_x448_scalar_mult(uint8_t out[56], const uint8_t scalar[56], const uint8_t point[56]);

/* ═══════════════════════════════════════════════════════════════════
 *  Ed25519 / Ed448 (RFC 8032)
 * ═══════════════════════════════════════════════════════════════════ */
void jp_ed25519_keygen(uint8_t pub[32], uint8_t priv[64]);
void jp_ed25519_derive_public_key(const uint8_t seed[32], uint8_t pub[32]);
void jp_ed25519_sign(const uint8_t priv[64], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
int jp_ed25519_verify(const uint8_t pub[32], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]);

void jp_ed448_keygen(uint8_t pub[57], uint8_t priv[114]);
void jp_ed448_sign(const uint8_t priv[114], const uint8_t* msg, size_t msg_len, uint8_t sig[114]);
int jp_ed448_verify(const uint8_t pub[57], const uint8_t* msg, size_t msg_len, const uint8_t sig[114]);

/* ═══════════════════════════════════════════════════════════════════
 *  ECDSA P-256/P-384/P-521
 * ═══════════════════════════════════════════════════════════════════ */
void jp_ecdsa_p256_keygen(uint8_t pub[64], uint8_t priv[32]);
void jp_ecdsa_p256_sign(const uint8_t priv[32], const uint8_t* msg, size_t msg_len, uint8_t sig[64]);
int jp_ecdsa_p256_verify(const uint8_t pub[64], const uint8_t* msg, size_t msg_len, const uint8_t sig[64]);
int jp_ecdsa_p256_ecdh(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[64]);

void jp_ecdsa_p384_keygen(uint8_t pub[96], uint8_t priv[48]);
void jp_ecdsa_p384_sign(const uint8_t priv[48], const uint8_t* msg, size_t msg_len, uint8_t sig[96]);
int jp_ecdsa_p384_verify(const uint8_t pub[96], const uint8_t* msg, size_t msg_len, const uint8_t sig[96]);
int jp_ecdsa_p384_ecdh(uint8_t shared[48], const uint8_t priv[48], const uint8_t pub[96]);

void jp_ecdsa_p521_keygen(uint8_t pub[132], uint8_t priv[66]);
void jp_ecdsa_p521_sign(const uint8_t priv[66], const uint8_t* msg, size_t msg_len, uint8_t sig[132]);
int jp_ecdsa_p521_verify(const uint8_t pub[132], const uint8_t* msg, size_t msg_len, const uint8_t sig[132]);

/* ═══════════════════════════════════════════════════════════════════
 *  SM2（国密椭圆曲线，GM/T 0003）
 * ═══════════════════════════════════════════════════════════════════ */
void jp_sm2_keygen(uint8_t pub[64], uint8_t priv[32]);
void jp_sm2_pub_from_priv(const uint8_t priv[32], uint8_t pub[64]);
void jp_sm2_sign(const uint8_t priv[32], const uint8_t* msg, size_t msg_len,
                 const uint8_t za[32], /* 可传 NULL 使用空标识 */ uint8_t sig[64]);
int jp_sm2_verify(const uint8_t pub[64], const uint8_t* msg, size_t msg_len,
                  const uint8_t za[32], const uint8_t sig[64]);
void jp_sm2_compute_za(const uint8_t* id, size_t id_len,
                       const uint8_t pub_x[32], const uint8_t pub_y[32], uint8_t za[32]);
int jp_sm2_ecdh(uint8_t shared[32], const uint8_t priv[32], const uint8_t* peer_pub, size_t peer_pub_len);

/* ═══════════════════════════════════════════════════════════════════
 *  RSA-2048 / RSA-4096（RFC 8017）
 *  密钥以固定宽度大端字节序列表示（bignum 完整字节数）。
 * ═══════════════════════════════════════════════════════════════════ */
#define JP_RSA_N_BYTES 256
#define JP_RSA4096_N_BYTES 512

typedef struct {
    uint8_t n[JP_RSA_N_BYTES]; /* 模数 */
    uint8_t e[JP_RSA_N_BYTES]; /* 公钥指数 */
} jp_rsa_pub;
typedef struct {
    uint8_t n[JP_RSA_N_BYTES];  /* modulus */
    uint8_t d[JP_RSA_N_BYTES];  /* private exponent */
    uint8_t e[JP_RSA_N_BYTES];  /* public exponent */
    uint8_t p[JP_RSA_N_BYTES];  /* prime1 */
    uint8_t q[JP_RSA_N_BYTES];  /* prime2 */
    uint8_t dP[JP_RSA_N_BYTES]; /* exponent1 */
    uint8_t dQ[JP_RSA_N_BYTES]; /* exponent2 */
    uint8_t qInv[JP_RSA_N_BYTES]; /* coefficient */
} jp_rsa_priv;

typedef struct {
    uint8_t n[JP_RSA4096_N_BYTES];
    uint8_t e[JP_RSA4096_N_BYTES];
} jp_rsa4096_pub;
typedef struct {
    uint8_t n[JP_RSA4096_N_BYTES];
    uint8_t d[JP_RSA4096_N_BYTES];
    uint8_t e[JP_RSA4096_N_BYTES];
    uint8_t p[JP_RSA4096_N_BYTES];
    uint8_t q[JP_RSA4096_N_BYTES];
    uint8_t dP[JP_RSA4096_N_BYTES];
    uint8_t dQ[JP_RSA4096_N_BYTES];
    uint8_t qInv[JP_RSA4096_N_BYTES];
} jp_rsa4096_priv;

/* 密钥生成（CRT 参数自动计算） */
int jp_rsa2048_keygen(jp_rsa_pub* pub, jp_rsa_priv* priv);
int jp_rsa4096_keygen(jp_rsa4096_pub* pub, jp_rsa4096_priv* priv);

/* 从标准 PKCS#1/DER 大端字节流导入密钥（不足宽度左补零，超出返回 0） */
int jp_rsa2048_pub_from_bytes(jp_rsa_pub* pub, const uint8_t* n, size_t n_len,
                              const uint8_t* e, size_t e_len);
int jp_rsa2048_priv_from_bytes(jp_rsa_priv* priv, const uint8_t* n, size_t n_len,
                               const uint8_t* d, size_t d_len);
int jp_rsa4096_pub_from_bytes(jp_rsa4096_pub* pub, const uint8_t* n, size_t n_len,
                              const uint8_t* e, size_t e_len);
int jp_rsa4096_priv_from_bytes(jp_rsa4096_priv* priv, const uint8_t* n, size_t n_len,
                               const uint8_t* d, size_t d_len);

/* PKCS#1 v1.5 加密/解密（rsa_encrypt 原语；明文 <= 密钥字节数 - 11） */
int jp_rsa2048_encrypt(const jp_rsa_pub* pub, const uint8_t* msg, size_t msg_len, uint8_t ct[256]);
int jp_rsa2048_decrypt(const jp_rsa_priv* priv, const uint8_t ct[256], uint8_t** out, size_t* out_len);
int jp_rsa4096_encrypt(const jp_rsa4096_pub* pub, const uint8_t* msg, size_t msg_len, uint8_t ct[512]);
int jp_rsa4096_decrypt(const jp_rsa4096_priv* priv, const uint8_t ct[512], uint8_t** out, size_t* out_len);

/* RSAES-OAEP（SHA-256，2048） */
int jp_rsa2048_oaep_encrypt(const jp_rsa_pub* pub, const uint8_t* msg, size_t msg_len, uint8_t ct[256]);
int jp_rsa2048_oaep_decrypt(const jp_rsa_priv* priv, const uint8_t ct[256], uint8_t** out, size_t* out_len);

/* RSASSA-PSS：hash=0(SHA-256) 1(SHA-384) 2(SHA-512)，salt 长 = 摘要长 */
int jp_rsa2048_pss_sign(const jp_rsa_priv* priv, const uint8_t* msg, size_t msg_len,
                        int hash, uint8_t sig[256]);
int jp_rsa2048_pss_verify(const jp_rsa_pub* pub, const uint8_t* msg, size_t msg_len,
                          int hash, const uint8_t sig[256]);
int jp_rsa4096_pss_sign(const jp_rsa4096_priv* priv, const uint8_t* msg, size_t msg_len,
                        int hash, uint8_t sig[512]);
int jp_rsa4096_pss_verify(const jp_rsa4096_pub* pub, const uint8_t* msg, size_t msg_len,
                          int hash, const uint8_t sig[512]);

/* RSASSA-PKCS1-v1_5：签名/验证（msg 为摘要，digest_prefix 为 DER DigestInfo 前缀） */
int jp_rsa2048_pkcs1_sign(const jp_rsa_priv* priv, const uint8_t* digest, size_t digest_len,
                          const uint8_t* digest_prefix, size_t prefix_len, uint8_t sig[256]);
int jp_rsa2048_pkcs1_verify(const jp_rsa_pub* pub, const uint8_t* digest, size_t digest_len,
                            const uint8_t* digest_prefix, size_t prefix_len, const uint8_t sig[256]);

/* ═══════════════════════════════════════════════════════════════════
 *  X.509 证书（RFC 5280）—— 解析 / 编码 / 验签
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct jp_x509_cert jp_x509_cert;
jp_x509_cert* jp_x509_cert_from_der(const uint8_t* der, size_t len);
jp_x509_cert* jp_x509_cert_from_pem(const char* pem, size_t len);
int jp_x509_cert_to_der(const jp_x509_cert* c, uint8_t** out, size_t* out_len);
char* jp_x509_cert_to_pem(const jp_x509_cert* c); /* 调用方 jp_free */
char* jp_x509_common_name(const jp_x509_cert* c); /* 调用方 jp_free */
char* jp_x509_issuer_name(const jp_x509_cert* c);  /* 调用方 jp_free */
int jp_x509_is_valid_now(const jp_x509_cert* c);
int jp_x509_is_valid_at(const jp_x509_cert* c, uint64_t now_unix);
int jp_x509_is_ca(const jp_x509_cert* c);
int jp_x509_verify_signature(const jp_x509_cert* c, const jp_x509_cert* issuer);
void jp_x509_cert_free(jp_x509_cert* c);

/* 从 PEM 私钥解析（PKCS#8/PKCS#1/SEC1/RFC 8410）。
 * 成功返回 KeyType（见 jp_key_type），priv/pub 为库内原始格式字节（jp_free），
 * 解析失败返回 JP_KEY_UNKNOWN。 */
int jp_x509_parse_private_key(const char* pem, size_t len,
                              uint8_t** priv, size_t* priv_len,
                              uint8_t** pub, size_t* pub_len);
enum {
    JP_KEY_RSA_2048 = 0,   /* 与 jpssl::x509::KeyType 一致 */
    JP_KEY_RSA_4096 = 1,
    JP_KEY_ED25519 = 2,
    JP_KEY_ED448 = 3,
    JP_KEY_ECDSA_P256 = 4,
    JP_KEY_ECDSA_P384 = 5,
    JP_KEY_SM2 = 6,
    JP_KEY_ECDSA_P521 = 7,
    JP_KEY_UNKNOWN = -1,
};

/* ═══════════════════════════════════════════════════════════════════
 *  TLS 1.3（高层 socket 连接封装，基于 tls_connection）
 * ═══════════════════════════════════════════════════════════════════ */
typedef struct jp_tls_conn jp_tls_conn;
jp_tls_conn* jp_tls_conn_new(void);
/* 客户端：TCP + TLS 1.3 握手，按系统信任库验证服务端证书链。
 * 成功返回 1；失败返回 0，err 非空时写入 malloc 的错误描述（jp_free）。 */
int jp_tls_client_connect(jp_tls_conn* c, const char* host, uint16_t port, char** err);
int jp_tls_send(jp_tls_conn* c, const uint8_t* data, size_t len, char** err);
/* 返回 malloc 的接收数据，调用方 jp_free；len 为实际字节数。 */
int jp_tls_recv(jp_tls_conn* c, uint8_t** data, size_t* len, char** err);
void jp_tls_close(jp_tls_conn* c);
void jp_tls_conn_free(jp_tls_conn* c);

/* ═══════════════════════════════════════════════════════════════════
 *  Base64（RFC 4648）
 * ═══════════════════════════════════════════════════════════════════ */
int jp_base64_encode(const uint8_t* data, size_t len, char** out); /* 调用方 jp_free */
int jp_base64_decode(const char* b64, size_t len, uint8_t** out, size_t* out_len);

/* ═══════════════════════════════════════════════════════════════════
 *  版本信息
 * ═══════════════════════════════════════════════════════════════════ */
const char* jp_version(void);

#ifdef __cplusplus
}
#endif

#endif /* JPSSL_C_BRIDGE_H */
