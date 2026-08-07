package io.github.jpssl

/**
 * jpssl 的 Kotlin 便捷封装：为 [Jpssl] 的 native 符号提供扩展函数，
 * 与 Java API 一一对应（同一 libjpssl.so）。
 */

/** 库版本号（与 [Jpssl.version] 一致）。 */
fun jpsslVersion(): String = Jpssl.version()

/** 密码学安全随机字节。 */
fun randomBytes(length: Int): ByteArray = Jpssl.randomBytes(length)

// ── Base64 ─────────────────────────────────────────────────────────────
fun ByteArray.base64Encode(): ByteArray = Jpssl.base64Encode(this)

fun ByteArray.base64Decode(): ByteArray = Jpssl.base64Decode(this)

// ── 哈希 ───────────────────────────────────────────────────────────────
fun ByteArray.sha1(): ByteArray = Jpssl.sha1(this)

fun ByteArray.sha256(): ByteArray = Jpssl.sha256(this)

fun ByteArray.sha384(): ByteArray = Jpssl.sha384(this)

fun ByteArray.sha512(): ByteArray = Jpssl.sha512(this)

fun ByteArray.sha3_256(): ByteArray = Jpssl.sha3_256(this)

fun ByteArray.sha3_384(): ByteArray = Jpssl.sha3_384(this)

fun ByteArray.sha3_512(): ByteArray = Jpssl.sha3_512(this)

fun ByteArray.sm3(): ByteArray = Jpssl.sm3(this)

// ── HMAC ───────────────────────────────────────────────────────────────
fun ByteArray.hmacSha256(key: ByteArray): ByteArray = Jpssl.hmacSha256(key, this)

fun ByteArray.hmacSha384(key: ByteArray): ByteArray = Jpssl.hmacSha384(key, this)

fun ByteArray.hmacSm3(key: ByteArray): ByteArray = Jpssl.hmacSm3(key, this)

// ── AES-GCM（返回/输入 = 密文||tag） ──────────────────────────────────
fun ByteArray.aesGcmEncrypt(key: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray =
    Jpssl.aesGcmEncrypt(key, iv, aad, this)

fun ByteArray.aesGcmDecrypt(key: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray =
    Jpssl.aesGcmDecrypt(key, iv, aad, this)

// ── ChaCha20-Poly1305（返回/输入 = 密文||tag） ────────────────────────
fun ByteArray.chacha20Poly1305Encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray =
    Jpssl.chacha20Poly1305Encrypt(key, nonce, aad, this)

fun ByteArray.chacha20Poly1305Decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray): ByteArray =
    Jpssl.chacha20Poly1305Decrypt(key, nonce, aad, this)

// ── X25519 ─────────────────────────────────────────────────────────────
/** @return Pair(私钥[32], 公钥[32]) */
fun x25519Keypair(): Pair<ByteArray, ByteArray> {
    val pair = Jpssl.x25519GenerateKeypair()
    return pair[0] as ByteArray to pair[1] as ByteArray
}

/** 计算与对端公钥的共享密钥（X25519 ECDH）。 */
fun ByteArray.x25519SharedSecret(peerPublicKey: ByteArray): ByteArray =
    Jpssl.x25519ScalarMult(this, peerPublicKey)

// ── Ed25519 ────────────────────────────────────────────────────────────
/** @return Pair(私钥[64], 公钥[32]) */
fun ed25519Keypair(): Pair<ByteArray, ByteArray> {
    val pair = Jpssl.ed25519GenerateKeypair()
    return pair[0] as ByteArray to pair[1] as ByteArray
}

fun ByteArray.ed25519DerivePublicKey(): ByteArray = Jpssl.ed25519DerivePublicKey(this)

fun ByteArray.ed25519Sign(message: ByteArray): ByteArray = Jpssl.ed25519Sign(this, message)

fun ByteArray.ed25519Verify(message: ByteArray, signature: ByteArray): Boolean =
    Jpssl.ed25519Verify(this, message, signature)

// ── SM2 ────────────────────────────────────────────────────────────────
/** @return Pair(私钥[32], 公钥[64]) */
fun sm2Keypair(): Pair<ByteArray, ByteArray> {
    val pair = Jpssl.sm2GenerateKeypair()
    return pair[0] as ByteArray to pair[1] as ByteArray
}

fun ByteArray.sm2Sign(message: ByteArray): ByteArray = Jpssl.sm2Sign(this, message)

fun ByteArray.sm2Verify(message: ByteArray, signature: ByteArray): Boolean =
    Jpssl.sm2Verify(this, message, signature)

fun ByteArray.sm2ComputeZa(id: ByteArray): ByteArray = Jpssl.sm2ComputeZa(id, this)

fun ByteArray.sm2PubFromPriv(): ByteArray = Jpssl.sm2PubFromPriv(this)

// ── SM4 ────────────────────────────────────────────────────────────────
/** ECB：数据长度必须为 16 的倍数。 */
fun ByteArray.sm4EcbEncrypt(key: ByteArray): ByteArray = Jpssl.sm4EcbEncrypt(key, this)

fun ByteArray.sm4EcbDecrypt(key: ByteArray): ByteArray = Jpssl.sm4EcbDecrypt(key, this)

/** CBC：自动 PKCS#7 填充/去填充。 */
fun ByteArray.sm4CbcEncrypt(key: ByteArray, iv: ByteArray): ByteArray =
    Jpssl.sm4CbcEncrypt(key, iv, this)

fun ByteArray.sm4CbcDecrypt(key: ByteArray, iv: ByteArray): ByteArray =
    Jpssl.sm4CbcDecrypt(key, iv, this)

// ── RSA（2048/4096，PKCS#1 v1.5） ──────────────────────────────────────
/** @return [Jpssl.RsaKey]，n/e/d 为固定长度大端字节数组。 */
fun rsaKeypair(bits: Int): Jpssl.RsaKey = Jpssl.rsaGenerateKeypair(bits)

fun Jpssl.RsaKey.encrypt(message: ByteArray): ByteArray =
    Jpssl.rsaEncrypt(modulus, publicExponent, message)

fun Jpssl.RsaKey.decrypt(ciphertext: ByteArray): ByteArray =
    Jpssl.rsaDecrypt(modulus, privateExponent, ciphertext)
