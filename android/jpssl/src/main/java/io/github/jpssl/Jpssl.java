package io.github.jpssl;

/**
 * jpssl — C++17 高性能密码学库（ARMv8/AArch64）的 Android JNI 封装。
 *
 * <p>静态 native 方法直接绑定 libjpssl.so（内部链接 libjpssl_cpu），
 * 由 {@code JNI_OnLoad → RegisterNatives} 注册，导出 Java/Kotlin 符号。
 *
 * <p>最低支持版本：Android API 21（arm64-v8a 基线，Android 5.0）。
 *
 * <p>约定：
 * <ul>
 *   <li>AES-GCM / ChaCha20-Poly1305 加密返回 {@code 密文||tag}（tag 固定 16 字节），
 *       解密输入同样为 {@code 密文||tag}。</li>
 *   <li>密钥对 native 方法返回 {@code Object[] {私钥, 公钥}}（顺序固定）。</li>
 *   <li>RSA 密钥以固定长度大端字节数组导出（n/e/d 各 256 或 512 字节）。</li>
 * </ul>
 */
public final class Jpssl {

    static {
        System.loadLibrary("jpssl");
    }

    private Jpssl() {
    }

    // ── 版本 / 随机数 ──────────────────────────────────────────────
    public static native String version();

    /** 密码学安全随机字节（基于系统 CSPRNG）。 */
    public static native byte[] randomBytes(int length);

    // ── Base64 (RFC 4648) ──────────────────────────────────────────
    public static native byte[] base64Encode(byte[] data);

    public static native byte[] base64Decode(byte[] data);

    // ── 哈希 ───────────────────────────────────────────────────────
    public static native byte[] sha1(byte[] data);

    public static native byte[] sha256(byte[] data);

    public static native byte[] sha384(byte[] data);

    public static native byte[] sha512(byte[] data);

    public static native byte[] sha3_256(byte[] data);

    public static native byte[] sha3_384(byte[] data);

    public static native byte[] sha3_512(byte[] data);

    public static native byte[] sm3(byte[] data);

    // ── HMAC ───────────────────────────────────────────────────────
    public static native byte[] hmacSha256(byte[] key, byte[] data);

    public static native byte[] hmacSha384(byte[] key, byte[] data);

    public static native byte[] hmacSm3(byte[] key, byte[] data);

    // ── AES-GCM（AEAD；返回/输入 = 密文||tag） ────────────────────
    public static native byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] aad,
                                              byte[] plaintext);

    public static native byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] aad,
                                              byte[] data);

    // ── ChaCha20-Poly1305（AEAD；返回/输入 = 密文||tag） ───────────
    public static native byte[] chacha20Poly1305Encrypt(byte[] key, byte[] nonce,
                                                        byte[] aad, byte[] plaintext);

    public static native byte[] chacha20Poly1305Decrypt(byte[] key, byte[] nonce,
                                                        byte[] aad, byte[] data);

    // ── X25519（ECDH） ─────────────────────────────────────────────
    /** @return Object[]{私钥[32], 公钥[32]} */
    public static native Object[] x25519GenerateKeypair();

    public static native byte[] x25519ScalarMult(byte[] privateKey,
                                                 byte[] peerPublicKey);

    // ── Ed25519（EdDSA） ───────────────────────────────────────────
    /** @return Object[]{私钥[64], 公钥[32]} */
    public static native Object[] ed25519GenerateKeypair();

    public static native byte[] ed25519DerivePublicKey(byte[] seed);

    public static native byte[] ed25519Sign(byte[] privateKey, byte[] message);

    public static native boolean ed25519Verify(byte[] publicKey, byte[] message,
                                               byte[] signature);

    // ── SM2（GM/T 0003） ───────────────────────────────────────────
    /** @return Object[]{私钥[32], 公钥[64]} */
    public static native Object[] sm2GenerateKeypair();

    public static native byte[] sm2Sign(byte[] privateKey, byte[] message);

    public static native boolean sm2Verify(byte[] publicKey, byte[] message,
                                           byte[] signature);

    public static native byte[] sm2ComputeZa(byte[] id, byte[] publicKey);

    public static native byte[] sm2PubFromPriv(byte[] privateKey);

    // ── SM4（GM/T 0002） ───────────────────────────────────────────
    /** ECB：data 长度必须为 16 的倍数。 */
    public static native byte[] sm4EcbEncrypt(byte[] key, byte[] data);

    public static native byte[] sm4EcbDecrypt(byte[] key, byte[] data);

    /** CBC：自动 PKCS#7 填充/去填充。 */
    public static native byte[] sm4CbcEncrypt(byte[] key, byte[] iv, byte[] data);

    public static native byte[] sm4CbcDecrypt(byte[] key, byte[] iv, byte[] data);

    // ── RSA（2048/4096，PKCS#1 v1.5） ──────────────────────────────
    /** @param bits 2048 或 4096 */
    public static native RsaKey rsaGenerateKeypair(int bits);

    public static native byte[] rsaEncrypt(byte[] modulus, byte[] publicExponent,
                                           byte[] message);

    public static native byte[] rsaDecrypt(byte[] modulus, byte[] privateExponent,
                                           byte[] ciphertext);

    /** RSA 密钥材料（大端字节数组，n/d/e 固定长度 256 或 512 字节）。 */
    public static final class RsaKey {
        public final byte[] modulus;
        public final byte[] publicExponent;
        public final byte[] privateExponent;

        RsaKey(byte[] modulus, byte[] publicExponent, byte[] privateExponent) {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
            this.privateExponent = privateExponent;
        }
    }
}
