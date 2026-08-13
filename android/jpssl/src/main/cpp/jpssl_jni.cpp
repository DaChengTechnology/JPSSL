/**
 * jpssl_jni.cpp — jpssl 密码学库的 Android JNI 桥（arm64-v8a）
 *
 * 通过 JNI_OnLoad 的 RegisterNatives 把 io.github.jpssl.Jpssl 的 native 方法
 * 绑定到本共享库（libjpssl.so），Java 与 Kotlin 均可直接调用。
 *
 * 覆盖算法：AES-GCM、ChaCha20-Poly1305、RSA(PKCS#1 v1.5)、SHA-1/256/384/512、
 * SHA3-256/384/512、SM2/3/4、HMAC-SHA256/SHA384/SM3、X25519、Ed25519、Base64、
 * CSPRNG 与库版本号。
 */
#include <jni.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "aes.hpp"
#include "base64.hpp"
#include "chacha20_poly1305.hpp"
#include "ed25519.hpp"
#include "hmac.hpp"
#include "rand_os.hpp"
#include "rsa.hpp"
#include "sha1.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "sha3.hpp"
#include "sm2.hpp"
#include "sm3.hpp"
#include "sm4.hpp"
#include "x25519.hpp"

using namespace jpssl;

// 与顶层 CMakeLists 的 project() 版本保持一致
#define JPSSL_JNI_VERSION "1.0.0"
#define JPSSL_CLASS "io/github/jpssl/Jpssl"

// ── 字节数组转换工具 ───────────────────────────────────────────────────
static std::vector<uint8_t> to_bytes(JNIEnv* env, jbyteArray arr) {
    if (!arr) return {};
    const jsize len = env->GetArrayLength(arr);
    std::vector<uint8_t> out(static_cast<size_t>(len));
    if (len > 0) {
        env->GetByteArrayRegion(arr, 0, len,
                                reinterpret_cast<jbyte*>(out.data()));
    }
    return out;
}

static jbyteArray to_jba(JNIEnv* env, const uint8_t* data, size_t len) {
    if (len > 0x7FFFFFFF) return nullptr;
    jbyteArray out = env->NewByteArray(static_cast<jsize>(len));
    if (out && len > 0) {
        env->SetByteArrayRegion(out, 0, static_cast<jsize>(len),
                                reinterpret_cast<const jbyte*>(data));
    }
    return out;
}

static jbyteArray to_jba(JNIEnv* env, const std::vector<uint8_t>& v) {
    return to_jba(env, v.data(), v.size());
}

static void throw_iae(JNIEnv* env, const char* msg) {
    jclass c = env->FindClass("java/lang/IllegalArgumentException");
    if (c) env->ThrowNew(c, msg);
}

static void throw_rte(JNIEnv* env, const char* msg) {
    jclass c = env->FindClass("java/lang/RuntimeException");
    if (c) env->ThrowNew(c, msg);
}

static jobjectArray jba_pair(JNIEnv* env, const uint8_t* a, size_t alen,
                             const uint8_t* b, size_t blen) {
    jclass ba_cls = env->FindClass("[B");
    if (!ba_cls) return nullptr;
    jobjectArray arr = env->NewObjectArray(2, ba_cls, nullptr);
    if (!arr) return nullptr;
    jbyteArray ja = to_jba(env, a, alen);
    jbyteArray jb = to_jba(env, b, blen);
    env->SetObjectArrayElement(arr, 0, ja);
    env->SetObjectArrayElement(arr, 1, jb);
    env->DeleteLocalRef(ja);
    env->DeleteLocalRef(jb);
    env->DeleteLocalRef(ba_cls);
    return arr;
}

static jobject make_rsa_key(JNIEnv* env, jbyteArray n, jbyteArray e,
                            jbyteArray d) {
    jclass cls = env->FindClass("io/github/jpssl/Jpssl$RsaKey");
    if (!cls) return nullptr;
    jmethodID ctor = env->GetMethodID(cls, "<init>", "([B[B[B)V");
    if (!ctor) return nullptr;
    return env->NewObject(cls, ctor, n, e, d);
}

// 一次性哈希（digest 定长）
template <size_t N>
static jbyteArray hash_once(JNIEnv* env, jbyteArray data,
                            void (*fn)(const uint8_t*, size_t, uint8_t*)) {
    std::vector<uint8_t> v = to_bytes(env, data);
    uint8_t digest[N];
    fn(v.data(), v.size(), digest);
    return to_jba(env, digest, N);
}

// ═══════════════════════════════════════════════════════════════════════
//  版本号
// ═══════════════════════════════════════════════════════════════════════
static jstring native_version(JNIEnv* env, jclass) {
    return env->NewStringUTF(JPSSL_JNI_VERSION);
}

// ═══════════════════════════════════════════════════════════════════════
//  CSPRNG
// ═══════════════════════════════════════════════════════════════════════
static jbyteArray native_random_bytes(JNIEnv* env, jclass, jint length) {
    if (length < 0) {
        throw_iae(env, "length 必须 >= 0");
        return nullptr;
    }
    std::vector<uint8_t> out(static_cast<size_t>(length));
    if (length > 0 && !os_rand_bytes(out.data(), out.size())) {
        throw_rte(env, "os_rand_bytes 失败");
        return nullptr;
    }
    return to_jba(env, out);
}

// ═══════════════════════════════════════════════════════════════════════
//  Base64 (RFC 4648)
// ═══════════════════════════════════════════════════════════════════════
static jbyteArray native_base64_encode(JNIEnv* env, jclass, jbyteArray data) {
    std::vector<uint8_t> v = to_bytes(env, data);
    std::string s = base64_encode(v.data(), v.size());
    return to_jba(env, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

static jbyteArray native_base64_decode(JNIEnv* env, jclass, jbyteArray data) {
    std::vector<uint8_t> v = to_bytes(env, data);
    std::string s(v.begin(), v.end());
    std::optional<std::vector<uint8_t>> r = base64_decode(s);
    if (!r) {
        throw_iae(env, "非法 base64 数据");
        return nullptr;
    }
    return to_jba(env, *r);
}

// ═══════════════════════════════════════════════════════════════════════
//  哈希：SHA-1 / SHA-256 / SHA-384 / SHA-512 / SHA3-256/384/512 / SM3
// ═══════════════════════════════════════════════════════════════════════
static jbyteArray native_sha1(JNIEnv* env, jclass, jbyteArray d) {
    return hash_once<20>(env, d, jpssl::sha1);
}
static jbyteArray native_sha256(JNIEnv* env, jclass, jbyteArray d) {
    return hash_once<32>(env, d, jpssl::sha256);
}
static jbyteArray native_sha384(JNIEnv* env, jclass, jbyteArray d) {
    return hash_once<48>(env, d, jpssl::sha384);
}
static jbyteArray native_sha512(JNIEnv* env, jclass, jbyteArray d) {
    return hash_once<64>(env, d, jpssl::sha512);
}

static jbyteArray native_sha3_256(JNIEnv* env, jclass, jbyteArray data) {
    std::vector<uint8_t> v = to_bytes(env, data);
    sha3_ctx ctx;
    sha3_256_init(&ctx);
    sha3_update(&ctx, v.data(), v.size());
    uint8_t d[32];
    sha3_final(&ctx, d);
    return to_jba(env, d, 32);
}
static jbyteArray native_sha3_384(JNIEnv* env, jclass, jbyteArray data) {
    std::vector<uint8_t> v = to_bytes(env, data);
    sha3_ctx ctx;
    sha3_384_init(&ctx);
    sha3_update(&ctx, v.data(), v.size());
    uint8_t d[48];
    sha3_final(&ctx, d);
    return to_jba(env, d, 48);
}
static jbyteArray native_sha3_512(JNIEnv* env, jclass, jbyteArray data) {
    std::vector<uint8_t> v = to_bytes(env, data);
    sha3_ctx ctx;
    sha3_512_init(&ctx);
    sha3_update(&ctx, v.data(), v.size());
    uint8_t d[64];
    sha3_final(&ctx, d);
    return to_jba(env, d, 64);
}
static jbyteArray native_sm3(JNIEnv* env, jclass, jbyteArray data) {
    std::vector<uint8_t> v = to_bytes(env, data);
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, v.data(), v.size());
    uint8_t d[32];
    sm3_final(&ctx, d);
    return to_jba(env, d, 32);
}

// ═══════════════════════════════════════════════════════════════════════
//  HMAC：SHA-256 / SHA-384 / SM3
// ═══════════════════════════════════════════════════════════════════════
static jbyteArray native_hmac_sha256(JNIEnv* env, jclass, jbyteArray keyJ,
                                     jbyteArray msgJ) {
    std::vector<uint8_t> k = to_bytes(env, keyJ);
    std::vector<uint8_t> m = to_bytes(env, msgJ);
    uint8_t mac[32];
    hmac_sha256(k.data(), k.size(), m.data(), m.size(), mac);
    return to_jba(env, mac, 32);
}
static jbyteArray native_hmac_sha384(JNIEnv* env, jclass, jbyteArray keyJ,
                                     jbyteArray msgJ) {
    std::vector<uint8_t> k = to_bytes(env, keyJ);
    std::vector<uint8_t> m = to_bytes(env, msgJ);
    uint8_t mac[48];
    hmac_sha384(k.data(), k.size(), m.data(), m.size(), mac);
    return to_jba(env, mac, 48);
}
static jbyteArray native_hmac_sm3(JNIEnv* env, jclass, jbyteArray keyJ,
                                  jbyteArray msgJ) {
    std::vector<uint8_t> k = to_bytes(env, keyJ);
    std::vector<uint8_t> m = to_bytes(env, msgJ);
    uint8_t mac[32];
    hmac_sm3(k.data(), k.size(), m.data(), m.size(), mac);
    return to_jba(env, mac, 32);
}

// ═══════════════════════════════════════════════════════════════════════
//  AES-GCM（AEAD；encrypt 输出 ct||tag，decrypt 输入 ct||tag）
// ═══════════════════════════════════════════════════════════════════════
static void make_aes_context(JNIEnv* env, const std::vector<uint8_t>& key,
                             aes_context* ctx) {
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        throw_iae(env, "AES 密钥必须为 16/24/32 字节");
        return;
    }
    if (key.size() == 16) {
        ctx->init(std::span<const uint8_t, 16>(key.data(), 16));
    } else if (key.size() == 24) {
        ctx->init(std::span<const uint8_t, 24>(key.data(), 24));
    } else {
        ctx->init(std::span<const uint8_t, 32>(key.data(), 32));
    }
}

static jbyteArray native_aes_gcm_encrypt(JNIEnv* env, jclass, jbyteArray keyJ,
                                         jbyteArray ivJ, jbyteArray aadJ,
                                         jbyteArray ptJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> iv = to_bytes(env, ivJ);
    std::vector<uint8_t> aad = to_bytes(env, aadJ);
    std::vector<uint8_t> pt = to_bytes(env, ptJ);
    if (iv.empty()) {
        throw_iae(env, "AES-GCM IV 不能为空");
        return nullptr;
    }
    aes_context ctx;
    make_aes_context(env, key, &ctx);
    if (env->ExceptionCheck()) return nullptr;

    std::vector<uint8_t> ct;
    uint8_t tag[16];
    aes_gcm_encrypt(ctx, iv.data(), iv.size(), pt, aad, ct, tag, 16);

    std::vector<uint8_t> out = ct;
    out.insert(out.end(), tag, tag + 16);
    return to_jba(env, out);
}

static jbyteArray native_aes_gcm_decrypt(JNIEnv* env, jclass, jbyteArray keyJ,
                                         jbyteArray ivJ, jbyteArray aadJ,
                                         jbyteArray dataJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> iv = to_bytes(env, ivJ);
    std::vector<uint8_t> aad = to_bytes(env, aadJ);
    std::vector<uint8_t> data = to_bytes(env, dataJ);
    if (iv.empty()) {
        throw_iae(env, "AES-GCM IV 不能为空");
        return nullptr;
    }
    if (data.size() < 16) {
        throw_iae(env, "AES-GCM 密文数据至少包含 16 字节 tag");
        return nullptr;
    }
    aes_context ctx;
    make_aes_context(env, key, &ctx);
    if (env->ExceptionCheck()) return nullptr;

    std::vector<uint8_t> ct(data.begin(), data.end() - 16);
    const uint8_t* tag = data.data() + ct.size();
    std::vector<uint8_t> pt;
    if (!aes_gcm_decrypt(ctx, iv.data(), iv.size(), ct, aad, tag, 16, pt)) {
        throw_iae(env, "AES-GCM 认证失败");
        return nullptr;
    }
    return to_jba(env, pt);
}

// ═══════════════════════════════════════════════════════════════════════
//  ChaCha20-Poly1305（AEAD；encrypt 输出 ct||tag，decrypt 输入 ct||tag）
// ═══════════════════════════════════════════════════════════════════════
static jbyteArray native_chacha20_poly1305_encrypt(JNIEnv* env, jclass,
                                                   jbyteArray keyJ,
                                                   jbyteArray nonceJ,
                                                   jbyteArray aadJ,
                                                   jbyteArray ptJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> nonce = to_bytes(env, nonceJ);
    std::vector<uint8_t> aad = to_bytes(env, aadJ);
    std::vector<uint8_t> pt = to_bytes(env, ptJ);
    if (key.size() != 32 || nonce.size() != 12) {
        throw_iae(env, "ChaCha20 密钥必须为 32 字节、nonce 为 12 字节");
        return nullptr;
    }
    std::vector<uint8_t> ct;
    uint8_t tag[16];
    chacha20_poly1305_encrypt(key.data(), nonce.data(), pt, aad, ct, tag);

    std::vector<uint8_t> out = ct;
    out.insert(out.end(), tag, tag + 16);
    return to_jba(env, out);
}

static jbyteArray native_chacha20_poly1305_decrypt(JNIEnv* env, jclass,
                                                   jbyteArray keyJ,
                                                   jbyteArray nonceJ,
                                                   jbyteArray aadJ,
                                                   jbyteArray dataJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> nonce = to_bytes(env, nonceJ);
    std::vector<uint8_t> aad = to_bytes(env, aadJ);
    std::vector<uint8_t> data = to_bytes(env, dataJ);
    if (key.size() != 32 || nonce.size() != 12) {
        throw_iae(env, "ChaCha20 密钥必须为 32 字节、nonce 为 12 字节");
        return nullptr;
    }
    if (data.size() < 16) {
        throw_iae(env, "ChaCha20-Poly1305 密文数据至少包含 16 字节 tag");
        return nullptr;
    }
    std::vector<uint8_t> ct(data.begin(), data.end() - 16);
    const uint8_t* tag = data.data() + ct.size();
    std::vector<uint8_t> pt;
    if (!chacha20_poly1305_decrypt(key.data(), nonce.data(), ct, aad, tag, pt)) {
        throw_iae(env, "ChaCha20-Poly1305 认证失败");
        return nullptr;
    }
    return to_jba(env, pt);
}

// ═══════════════════════════════════════════════════════════════════════
//  X25519（ECDH）
// ═══════════════════════════════════════════════════════════════════════
static jobjectArray native_x25519_generate_keypair(JNIEnv* env, jclass) {
    uint8_t priv[32], pub[32];
    x25519_generate_keypair(pub, priv);
    return jba_pair(env, priv, 32, pub, 32);
}

static jbyteArray native_x25519_scalar_mult(JNIEnv* env, jclass,
                                            jbyteArray privJ,
                                            jbyteArray peerJ) {
    std::vector<uint8_t> priv = to_bytes(env, privJ);
    std::vector<uint8_t> peer = to_bytes(env, peerJ);
    if (priv.size() != 32 || peer.size() != 32) {
        throw_iae(env, "X25519 密钥必须为 32 字节");
        return nullptr;
    }
    uint8_t out[32];
    x25519_scalar_mult(out, priv.data(), peer.data());
    return to_jba(env, out, 32);
}

// ═══════════════════════════════════════════════════════════════════════
//  Ed25519（EdDSA）
// ═══════════════════════════════════════════════════════════════════════
static jobjectArray native_ed25519_generate_keypair(JNIEnv* env, jclass) {
    uint8_t pub[32], priv[64];
    ed25519_keygen(pub, priv);
    return jba_pair(env, priv, 64, pub, 32);
}

static jbyteArray native_ed25519_derive_public_key(JNIEnv* env, jclass,
                                                   jbyteArray seedJ) {
    std::vector<uint8_t> seed = to_bytes(env, seedJ);
    if (seed.size() != 32) {
        throw_iae(env, "Ed25519 种子必须为 32 字节");
        return nullptr;
    }
    uint8_t pub[32];
    ed25519_derive_public_key(seed.data(), pub);
    return to_jba(env, pub, 32);
}

static jbyteArray native_ed25519_sign(JNIEnv* env, jclass, jbyteArray privJ,
                                      jbyteArray msgJ) {
    std::vector<uint8_t> priv = to_bytes(env, privJ);
    std::vector<uint8_t> msg = to_bytes(env, msgJ);
    if (priv.size() != 64) {
        throw_iae(env, "Ed25519 私钥必须为 64 字节（含种子与公钥）");
        return nullptr;
    }
    uint8_t sig[64];
    ed25519_sign(priv.data(), msg.data(), msg.size(), sig);
    return to_jba(env, sig, 64);
}

static jboolean native_ed25519_verify(JNIEnv* env, jclass, jbyteArray pubJ,
                                      jbyteArray msgJ, jbyteArray sigJ) {
    std::vector<uint8_t> pub = to_bytes(env, pubJ);
    std::vector<uint8_t> msg = to_bytes(env, msgJ);
    std::vector<uint8_t> sig = to_bytes(env, sigJ);
    if (pub.size() != 32 || sig.size() != 64) {
        throw_iae(env, "Ed25519 公钥必须为 32 字节、签名必须为 64 字节");
        return JNI_FALSE;
    }
    return ed25519_verify(pub.data(), msg.data(), msg.size(), sig.data())
               ? JNI_TRUE
               : JNI_FALSE;
}

// ═══════════════════════════════════════════════════════════════════════
//  SM2（GM/T 0003）
// ═══════════════════════════════════════════════════════════════════════
static jobjectArray native_sm2_generate_keypair(JNIEnv* env, jclass) {
    uint8_t pub[64], priv[32];
    sm2_keygen(pub, priv);
    return jba_pair(env, priv, 32, pub, 64);
}

static jbyteArray native_sm2_sign(JNIEnv* env, jclass, jbyteArray privJ,
                                  jbyteArray msgJ) {
    std::vector<uint8_t> priv = to_bytes(env, privJ);
    std::vector<uint8_t> msg = to_bytes(env, msgJ);
    if (priv.size() != 32) {
        throw_iae(env, "SM2 私钥必须为 32 字节");
        return nullptr;
    }
    uint8_t sig[64];
    sm2_sign(priv.data(), msg.data(), msg.size(), sig);
    return to_jba(env, sig, 64);
}

static jboolean native_sm2_verify(JNIEnv* env, jclass, jbyteArray pubJ,
                                  jbyteArray msgJ, jbyteArray sigJ) {
    std::vector<uint8_t> pub = to_bytes(env, pubJ);
    std::vector<uint8_t> msg = to_bytes(env, msgJ);
    std::vector<uint8_t> sig = to_bytes(env, sigJ);
    if (pub.size() != 64 || sig.size() != 64) {
        throw_iae(env, "SM2 公钥与签名必须为 64 字节");
        return JNI_FALSE;
    }
    return sm2_verify(pub.data(), msg.data(), msg.size(), sig.data())
               ? JNI_TRUE
               : JNI_FALSE;
}

static jbyteArray native_sm2_compute_za(JNIEnv* env, jclass, jbyteArray idJ,
                                        jbyteArray pubJ) {
    std::vector<uint8_t> id = to_bytes(env, idJ);
    std::vector<uint8_t> pub = to_bytes(env, pubJ);
    if (pub.size() != 64) {
        throw_iae(env, "SM2 公钥必须为 64 字节");
        return nullptr;
    }
    uint8_t za[32];
    sm2_compute_za(id.data(), id.size(), pub.data(), pub.data() + 32, za);
    return to_jba(env, za, 32);
}

static jbyteArray native_sm2_pub_from_priv(JNIEnv* env, jclass,
                                           jbyteArray privJ) {
    std::vector<uint8_t> priv = to_bytes(env, privJ);
    if (priv.size() != 32) {
        throw_iae(env, "SM2 私钥必须为 32 字节");
        return nullptr;
    }
    uint8_t pub[64];
    sm2_pub_from_priv(priv.data(), pub);
    return to_jba(env, pub, 64);
}

// ═══════════════════════════════════════════════════════════════════════
//  SM4（GM/T 0002；ECB 要求数据为 16 字节倍数，CBC 自动 PKCS#7）
// ═══════════════════════════════════════════════════════════════════════
static bool make_sm4_ctx(JNIEnv* env, const std::vector<uint8_t>& key,
                         sm4_ctx* ctx) {
    if (key.size() != 16) {
        throw_iae(env, "SM4 密钥必须为 16 字节");
        return false;
    }
    sm4_init(ctx, key.data());
    return true;
}

static jbyteArray native_sm4_ecb_encrypt(JNIEnv* env, jclass, jbyteArray keyJ,
                                         jbyteArray dataJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> data = to_bytes(env, dataJ);
    sm4_ctx ctx;
    if (!make_sm4_ctx(env, key, &ctx)) return nullptr;
    if (data.size() % 16 != 0) {
        throw_iae(env, "SM4-ECB 数据长度必须为 16 字节的倍数");
        return nullptr;
    }
    std::vector<uint8_t> out(data.size());
    sm4_ecb_encrypt(&ctx, data, out);
    return to_jba(env, out);
}

static jbyteArray native_sm4_ecb_decrypt(JNIEnv* env, jclass, jbyteArray keyJ,
                                         jbyteArray dataJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> data = to_bytes(env, dataJ);
    sm4_ctx ctx;
    if (!make_sm4_ctx(env, key, &ctx)) return nullptr;
    if (data.size() % 16 != 0) {
        throw_iae(env, "SM4-ECB 数据长度必须为 16 字节的倍数");
        return nullptr;
    }
    std::vector<uint8_t> out(data.size());
    sm4_ecb_decrypt(&ctx, data, out);
    return to_jba(env, out);
}

static jbyteArray native_sm4_cbc_encrypt(JNIEnv* env, jclass, jbyteArray keyJ,
                                         jbyteArray ivJ, jbyteArray dataJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> iv = to_bytes(env, ivJ);
    std::vector<uint8_t> data = to_bytes(env, dataJ);
    if (iv.size() != 16) {
        throw_iae(env, "SM4-CBC IV 必须为 16 字节");
        return nullptr;
    }
    sm4_ctx ctx;
    if (!make_sm4_ctx(env, key, &ctx)) return nullptr;
    std::vector<uint8_t> out = sm4_cbc_encrypt(&ctx, iv.data(), data);
    return to_jba(env, out);
}

static jbyteArray native_sm4_cbc_decrypt(JNIEnv* env, jclass, jbyteArray keyJ,
                                         jbyteArray ivJ, jbyteArray dataJ) {
    std::vector<uint8_t> key = to_bytes(env, keyJ);
    std::vector<uint8_t> iv = to_bytes(env, ivJ);
    std::vector<uint8_t> data = to_bytes(env, dataJ);
    if (iv.size() != 16) {
        throw_iae(env, "SM4-CBC IV 必须为 16 字节");
        return nullptr;
    }
    sm4_ctx ctx;
    if (!make_sm4_ctx(env, key, &ctx)) return nullptr;
    std::vector<uint8_t> out = sm4_cbc_decrypt(&ctx, iv.data(), data);
    return to_jba(env, out);
}

// ═══════════════════════════════════════════════════════════════════════
//  RSA（2048/4096，PKCS#1 v1.5）
//  密钥以固定长度大端字节导出：n=256/512，e=256/512，d=256/512。
// ═══════════════════════════════════════════════════════════════════════
static jbyteArray bn2048_to_jba(JNIEnv* env, const rsa_bignum& bn) {
    uint8_t buf[256];
    bn.to_bytes(buf);
    return to_jba(env, buf, 256);
}
static jbyteArray bn4096_to_jba(JNIEnv* env, const rsa4096_bignum& bn) {
    uint8_t buf[512];
    bn.to_bytes(buf);
    return to_jba(env, buf, 512);
}

static jobject native_rsa_generate_keypair(JNIEnv* env, jclass, jint bits) {
    if (bits == 2048) {
        rsa_public_key pub;
        rsa_private_key prv;
        if (!rsa_keygen(pub, prv)) {
            throw_rte(env, "RSA-2048 密钥生成失败");
            return nullptr;
        }
        jbyteArray n = bn2048_to_jba(env, prv.n);
        jbyteArray e = bn2048_to_jba(env, prv.e);
        jbyteArray d = bn2048_to_jba(env, prv.d);
        return make_rsa_key(env, n, e, d);
    } else if (bits == 4096) {
        rsa4096_public_key pub;
        rsa4096_private_key prv;
        if (!rsa4096_keygen(pub, prv)) {
            throw_rte(env, "RSA-4096 密钥生成失败");
            return nullptr;
        }
        jbyteArray n = bn4096_to_jba(env, prv.n);
        jbyteArray e = bn4096_to_jba(env, prv.e);
        jbyteArray d = bn4096_to_jba(env, prv.d);
        return make_rsa_key(env, n, e, d);
    }
    throw_iae(env, "bits 必须为 2048 或 4096");
    return nullptr;
}

static jbyteArray native_rsa_encrypt(JNIEnv* env, jclass, jbyteArray nJ,
                                     jbyteArray eJ, jbyteArray msgJ) {
    std::vector<uint8_t> n = to_bytes(env, nJ);
    std::vector<uint8_t> e = to_bytes(env, eJ);
    std::vector<uint8_t> msg = to_bytes(env, msgJ);
    if (n.size() != 256 && n.size() != 512) {
        throw_iae(env, "RSA 模数必须为 256 或 512 字节");
        return nullptr;
    }
    std::vector<uint8_t> ct(n.size());
    if (n.size() == 256) {
        rsa_public_key pub;
        pub.n = rsa_bignum::from_bytes(n.data(), n.size());
        pub.e = rsa_bignum::from_bytes(e.data(), e.size());
        rsa_encrypt(pub, msg, ct.data());
    } else {
        rsa4096_public_key pub;
        pub.n = rsa4096_bignum::from_bytes(n.data(), n.size());
        pub.e = rsa4096_bignum::from_bytes(e.data(), e.size());
        rsa4096_encrypt(pub, msg, ct.data());
    }
    return to_jba(env, ct);
}

static jbyteArray native_rsa_decrypt(JNIEnv* env, jclass, jbyteArray nJ,
                                     jbyteArray dJ, jbyteArray ctJ) {
    std::vector<uint8_t> n = to_bytes(env, nJ);
    std::vector<uint8_t> d = to_bytes(env, dJ);
    std::vector<uint8_t> ct = to_bytes(env, ctJ);
    if (n.size() != 256 && n.size() != 512) {
        throw_iae(env, "RSA 模数必须为 256 或 512 字节");
        return nullptr;
    }
    if (ct.size() != n.size()) {
        throw_iae(env, "RSA 密文长度必须等于模数长度");
        return nullptr;
    }
    std::vector<uint8_t> pt;
    bool ok = false;
    if (n.size() == 256) {
        rsa_private_key prv;
        prv.n = rsa_bignum::from_bytes(n.data(), n.size());
        prv.d = rsa_bignum::from_bytes(d.data(), d.size());
        ok = rsa_decrypt(prv, ct.data(), pt);
    } else {
        rsa4096_private_key prv;
        prv.n = rsa4096_bignum::from_bytes(n.data(), n.size());
        prv.d = rsa4096_bignum::from_bytes(d.data(), d.size());
        ok = rsa4096_decrypt(prv, ct.data(), pt);
    }
    if (!ok) {
        throw_iae(env, "RSA 解密失败");
        return nullptr;
    }
    return to_jba(env, pt);
}

// ═══════════════════════════════════════════════════════════════════════
//  JNI 注册表（导出 Java/Kotlin 符号）
// ═══════════════════════════════════════════════════════════════════════
static const JNINativeMethod kMethods[] = {
    {"version", "()Ljava/lang/String;", (void*)native_version},
    {"randomBytes", "(I)[B", (void*)native_random_bytes},

    {"base64Encode", "([B)[B", (void*)native_base64_encode},
    {"base64Decode", "([B)[B", (void*)native_base64_decode},

    {"sha1", "([B)[B", (void*)native_sha1},
    {"sha256", "([B)[B", (void*)native_sha256},
    {"sha384", "([B)[B", (void*)native_sha384},
    {"sha512", "([B)[B", (void*)native_sha512},
    {"sha3_256", "([B)[B", (void*)native_sha3_256},
    {"sha3_384", "([B)[B", (void*)native_sha3_384},
    {"sha3_512", "([B)[B", (void*)native_sha3_512},
    {"sm3", "([B)[B", (void*)native_sm3},

    {"hmacSha256", "([B[B)[B", (void*)native_hmac_sha256},
    {"hmacSha384", "([B[B)[B", (void*)native_hmac_sha384},
    {"hmacSm3", "([B[B)[B", (void*)native_hmac_sm3},

    {"aesGcmEncrypt", "([B[B[B[B)[B", (void*)native_aes_gcm_encrypt},
    {"aesGcmDecrypt", "([B[B[B[B)[B", (void*)native_aes_gcm_decrypt},

    {"chacha20Poly1305Encrypt", "([B[B[B[B)[B",
     (void*)native_chacha20_poly1305_encrypt},
    {"chacha20Poly1305Decrypt", "([B[B[B[B)[B",
     (void*)native_chacha20_poly1305_decrypt},

    {"x25519GenerateKeypair", "()[Ljava/lang/Object;",
     (void*)native_x25519_generate_keypair},
    {"x25519ScalarMult", "([B[B)[B", (void*)native_x25519_scalar_mult},

    {"ed25519GenerateKeypair", "()[Ljava/lang/Object;",
     (void*)native_ed25519_generate_keypair},
    {"ed25519DerivePublicKey", "([B)[B", (void*)native_ed25519_derive_public_key},
    {"ed25519Sign", "([B[B)[B", (void*)native_ed25519_sign},
    {"ed25519Verify", "([B[B[B)Z", (void*)native_ed25519_verify},

    {"sm2GenerateKeypair", "()[Ljava/lang/Object;",
     (void*)native_sm2_generate_keypair},
    {"sm2Sign", "([B[B)[B", (void*)native_sm2_sign},
    {"sm2Verify", "([B[B[B)Z", (void*)native_sm2_verify},
    {"sm2ComputeZa", "([B[B)[B", (void*)native_sm2_compute_za},
    {"sm2PubFromPriv", "([B)[B", (void*)native_sm2_pub_from_priv},

    {"sm4EcbEncrypt", "([B[B)[B", (void*)native_sm4_ecb_encrypt},
    {"sm4EcbDecrypt", "([B[B)[B", (void*)native_sm4_ecb_decrypt},
    {"sm4CbcEncrypt", "([B[B[B)[B", (void*)native_sm4_cbc_encrypt},
    {"sm4CbcDecrypt", "([B[B[B)[B", (void*)native_sm4_cbc_decrypt},

    {"rsaGenerateKeypair", "(I)Lio/github/jpssl/Jpssl$RsaKey;",
     (void*)native_rsa_generate_keypair},
    {"rsaEncrypt", "([B[B[B)[B", (void*)native_rsa_encrypt},
    {"rsaDecrypt", "([B[B[B)[B", (void*)native_rsa_decrypt},
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass(JPSSL_CLASS);
    if (!cls) return JNI_ERR;
    const jint count =
        static_cast<jint>(sizeof(kMethods) / sizeof(kMethods[0]));
    if (env->RegisterNatives(cls, kMethods, count) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
