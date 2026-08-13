// JPSsl.swift — jpssl 密码学库的 Swift 封装层
//
// 底层 C 桥接模块为 JPSslC（见 ios/bridge/jpssl.h + module.modulemap），
// 本文件把 C 函数封装为类型安全、惯用的 Swift API。
//
// 约定：
//   - 字节数组一律 [UInt8]；变长输出由本层负责拷贝并释放底层缓冲区；
//   - 布尔结果映射为 Swift Bool（C 的 int 1/0）；
//   - 失败返回 nil / throw JPSslError（仅在 C 层返回 0 时）。
//
// 最低支持：iOS 13.0 / arm64（ARMv8）。

import Foundation
import JPSslC

// MARK: - 公共错误

public enum JPSslError: Error {
    case operationFailed
    case invalidInput
}

// MARK: - 命名空间

public enum JPSsl {

    // MARK: 随机数

    public enum Random {
        /// 生成 count 字节密码学安全随机数；失败返回 nil。
        public static func secureBytes(_ count: Int) -> [UInt8]? {
            var out = [UInt8](repeating: 0, count: count)
            let ok = out.withUnsafeMutableBytes {
                jp_secure_rand($0.bindMemory(to: UInt8.self).baseAddress, count)
            }
            return ok != 0 ? out : nil
        }
    }

    // MARK: - 哈希

    /// 一次性哈希 + 流式上下文。
    public enum Hash {

        public final class StreamingHasher {
            fileprivate let updateFn: ([UInt8]) -> Void
            fileprivate let finalFn: () -> [UInt8]

            public init(update: @escaping ([UInt8]) -> Void, final: @escaping () -> [UInt8]) {
                self.updateFn = update
                self.finalFn = final
            }
            public func update(_ data: [UInt8]) { updateFn(data) }
            public func final() -> [UInt8] { finalFn() }
        }

        public enum SHA1 {
            public static func hash(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 20)
                data.withUnsafeBytes { jp_sha1($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func streaming() -> StreamingHasher {
                let ctx = jp_sha1_ctx_new()!
                return StreamingHasher(
                    update: { d in d.withUnsafeBytes { jp_sha1_update(ctx, $0.bindMemory(to: UInt8.self).baseAddress, d.count) } },
                    final: {
                        var out = [UInt8](repeating: 0, count: 20)
                        jp_sha1_final(ctx, &out)
                        jp_sha1_ctx_free(ctx)
                        return out
                    })
            }
        }

        public enum SHA256 {
            public static func hash(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 32)
                data.withUnsafeBytes { jp_sha256($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func streaming() -> StreamingHasher {
                let ctx = jp_sha256_ctx_new()!
                return StreamingHasher(
                    update: { d in d.withUnsafeBytes { jp_sha256_update(ctx, $0.bindMemory(to: UInt8.self).baseAddress, d.count) } },
                    final: {
                        var out = [UInt8](repeating: 0, count: 32)
                        jp_sha256_final(ctx, &out)
                        jp_sha256_ctx_free(ctx)
                        return out
                    })
            }
        }

        public enum SHA384 {
            public static func hash(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 48)
                data.withUnsafeBytes { jp_sha384($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func streaming() -> StreamingHasher { sha512Streaming(is384: true) }
        }

        public enum SHA512 {
            public static func hash(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 64)
                data.withUnsafeBytes { jp_sha512($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func streaming() -> StreamingHasher { sha512Streaming(is384: false) }
        }

        private static func sha512Streaming(is384: Bool) -> StreamingHasher {
            let ctx = jp_sha512_ctx_new(is384 ? 1 : 0)!
            return StreamingHasher(
                update: { d in d.withUnsafeBytes { jp_sha512_update(ctx, $0.bindMemory(to: UInt8.self).baseAddress, d.count) } },
                final: {
                    var out = [UInt8](repeating: 0, count: is384 ? 48 : 64)
                    jp_sha512_final(ctx, &out)
                    jp_sha512_ctx_free(ctx)
                    return out
                })
        }

        public enum SHA3 {
            public static func hash256(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 32)
                data.withUnsafeBytes { jp_sha3_256($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func hash384(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 48)
                data.withUnsafeBytes { jp_sha3_384($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func hash512(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 64)
                data.withUnsafeBytes { jp_sha3_512($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func streaming(variant: Int) -> StreamingHasher {
                let ctx = jp_sha3_ctx_new(Int32(variant))!
                let n = variant == 0 ? 32 : (variant == 1 ? 48 : 64)
                return StreamingHasher(
                    update: { d in d.withUnsafeBytes { jp_sha3_update(ctx, $0.bindMemory(to: UInt8.self).baseAddress, d.count) } },
                    final: {
                        var out = [UInt8](repeating: 0, count: n)
                        jp_sha3_final(ctx, &out)
                        jp_sha3_ctx_free(ctx)
                        return out
                    })
            }
        }

        public enum SHAKE {
            public static func shake128(_ input: [UInt8], outputLength: Int) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: outputLength)
                input.withUnsafeBytes { jp_shake128($0.bindMemory(to: UInt8.self).baseAddress, input.count, &out, outputLength) }
                return out
            }
            public static func shake256(_ input: [UInt8], outputLength: Int) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: outputLength)
                input.withUnsafeBytes { jp_shake256($0.bindMemory(to: UInt8.self).baseAddress, input.count, &out, outputLength) }
                return out
            }
        }

        public enum SM3 {
            public static func hash(_ data: [UInt8]) -> [UInt8] {
                var out = [UInt8](repeating: 0, count: 32)
                data.withUnsafeBytes { jp_sm3($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }
                return out
            }
            public static func streaming() -> StreamingHasher {
                let ctx = jp_sm3_ctx_new()!
                return StreamingHasher(
                    update: { d in d.withUnsafeBytes { jp_sm3_update(ctx, $0.bindMemory(to: UInt8.self).baseAddress, d.count) } },
                    final: {
                        var out = [UInt8](repeating: 0, count: 32)
                        jp_sm3_final(ctx, &out)
                        jp_sm3_ctx_free(ctx)
                        return out
                    })
            }
        }
    }

    // MARK: - HMAC / HKDF

    public enum MAC {
        public static func hmacSHA256(key: [UInt8], message: [UInt8]) -> [UInt8] {
            var mac = [UInt8](repeating: 0, count: 32)
            key.withUnsafeBytes { k in
                message.withUnsafeBytes { m in
                    jp_hmac_sha256(k.bindMemory(to: UInt8.self).baseAddress, key.count,
                                   m.bindMemory(to: UInt8.self).baseAddress, message.count, &mac)
                }
            }
            return mac
        }
        public static func hmacSHA384(key: [UInt8], message: [UInt8]) -> [UInt8] {
            var mac = [UInt8](repeating: 0, count: 48)
            key.withUnsafeBytes { k in
                message.withUnsafeBytes { m in
                    jp_hmac_sha384(k.bindMemory(to: UInt8.self).baseAddress, key.count,
                                   m.bindMemory(to: UInt8.self).baseAddress, message.count, &mac)
                }
            }
            return mac
        }
        public static func hmacSM3(key: [UInt8], message: [UInt8]) -> [UInt8] {
            var mac = [UInt8](repeating: 0, count: 32)
            key.withUnsafeBytes { k in
                message.withUnsafeBytes { m in
                    jp_hmac_sm3(k.bindMemory(to: UInt8.self).baseAddress, key.count,
                                m.bindMemory(to: UInt8.self).baseAddress, message.count, &mac)
                }
            }
            return mac
        }
    }

    public enum KDF {
        public static func hkdfSHA256(salt: [UInt8], ikm: [UInt8], info: [UInt8], outputLength: Int) -> [UInt8]? {
            var prk = [UInt8](repeating: 0, count: 32)
            var okm = [UInt8](repeating: 0, count: outputLength)
            salt.withUnsafeBytes { jp_hkdf_extract_sha256($0.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                                          ikm.withUnsafeBytes { $0.bindMemory(to: UInt8.self).baseAddress }, ikm.count, &prk) }
            info.withUnsafeBytes { jp_hkdf_expand_sha256(prk, 32, $0.bindMemory(to: UInt8.self).baseAddress, info.count, &okm, outputLength) }
            return okm
        }
        public static func hkdfSHA384(salt: [UInt8], ikm: [UInt8], info: [UInt8], outputLength: Int) -> [UInt8]? {
            var prk = [UInt8](repeating: 0, count: 48)
            var okm = [UInt8](repeating: 0, count: outputLength)
            salt.withUnsafeBytes { jp_hkdf_extract_sha384($0.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                                          ikm.withUnsafeBytes { $0.bindMemory(to: UInt8.self).baseAddress }, ikm.count, &prk) }
            info.withUnsafeBytes { jp_hkdf_expand_sha384(prk, 48, $0.bindMemory(to: UInt8.self).baseAddress, info.count, &okm, outputLength) }
            return okm
        }
        public static func hkdfSM3(salt: [UInt8], ikm: [UInt8], info: [UInt8], outputLength: Int) -> [UInt8]? {
            var prk = [UInt8](repeating: 0, count: 32)
            var okm = [UInt8](repeating: 0, count: outputLength)
            salt.withUnsafeBytes { jp_hkdf_extract_sm3($0.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                                       ikm.withUnsafeBytes { $0.bindMemory(to: UInt8.self).baseAddress }, ikm.count, &prk) }
            info.withUnsafeBytes { jp_hkdf_expand_sm3(prk, 32, $0.bindMemory(to: UInt8.self).baseAddress, info.count, &okm, outputLength) }
            return okm
        }
    }

    // MARK: - AES

    public final class AES {
        let ctx: OpaquePointer

        public init?(key: [UInt8]) {
            guard let c = key.withUnsafeBytes({ jp_aes_init($0.bindMemory(to: UInt8.self).baseAddress, key.count) }) else { return nil }
            self.ctx = c
        }
        deinit { jp_aes_free(ctx) }

        public func encryptBlock(_ block: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 16)
            block.withUnsafeBytes { jp_aes_encrypt_block(ctx, $0.bindMemory(to: UInt8.self).baseAddress, &out) }
            return out
        }
        public func decryptBlock(_ block: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 16)
            block.withUnsafeBytes { jp_aes_decrypt_block(ctx, $0.bindMemory(to: UInt8.self).baseAddress, &out) }
            return out
        }
        public func ecbEncrypt(_ data: [UInt8]) -> [UInt8]? {
            guard data.count % 16 == 0 else { return nil }
            var out = [UInt8](repeating: 0, count: data.count)
            let ok = data.withUnsafeBytes { jp_aes_ecb_encrypt(ctx, $0.bindMemory(to: UInt8.self).baseAddress, &out, data.count) }
            return ok != 0 ? out : nil
        }
        public func ecbDecrypt(_ data: [UInt8]) -> [UInt8]? {
            guard data.count % 16 == 0 else { return nil }
            var out = [UInt8](repeating: 0, count: data.count)
            let ok = data.withUnsafeBytes { jp_aes_ecb_decrypt(ctx, $0.bindMemory(to: UInt8.self).baseAddress, &out, data.count) }
            return ok != 0 ? out : nil
        }
        public func cbcEncrypt(iv: [UInt8], plaintext: [UInt8]) -> [UInt8]? {
            var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
            let ok = plaintext.withUnsafeBytes {
                jp_aes_cbc_encrypt(ctx, iv, $0.bindMemory(to: UInt8.self).baseAddress, plaintext.count, &out, &len)
            }
            return ok != 0 ? copyFree(&out, len) : nil
        }
        public func cbcDecrypt(iv: [UInt8], ciphertext: [UInt8]) -> [UInt8]? {
            var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
            let ok = ciphertext.withUnsafeBytes {
                jp_aes_cbc_decrypt(ctx, iv, $0.bindMemory(to: UInt8.self).baseAddress, ciphertext.count, &out, &len)
            }
            return ok != 0 ? copyFree(&out, len) : nil
        }
        public func gcmEncrypt(iv: [UInt8], plaintext: [UInt8], aad: [UInt8] = [], tagLength: Int = 16) -> (ciphertext: [UInt8], tag: [UInt8])? {
            var ct = [UInt8](repeating: 0, count: plaintext.count)
            var tag = [UInt8](repeating: 0, count: tagLength)
            let ok = iv.withUnsafeBytes { ivp in
                plaintext.withUnsafeBytes { pp in
                    aad.withUnsafeBytes { ap in
                        jp_aes_gcm_encrypt(ctx, ivp.bindMemory(to: UInt8.self).baseAddress, iv.count,
                                           pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           &ct, &tag, tagLength)
                    }
                }
            }
            return ok != 0 ? (ct, tag) : nil
        }
        public func gcmDecrypt(iv: [UInt8], ciphertext: [UInt8], aad: [UInt8] = [], tag: [UInt8]) -> [UInt8]? {
            var pt = [UInt8](repeating: 0, count: ciphertext.count)
            let ok = iv.withUnsafeBytes { ivp in
                ciphertext.withUnsafeBytes { cp in
                    aad.withUnsafeBytes { ap in
                        jp_aes_gcm_decrypt(ctx, ivp.bindMemory(to: UInt8.self).baseAddress, iv.count,
                                           cp.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           tag, tag.count, &pt)
                    }
                }
            }
            return ok != 0 ? pt : nil
        }
        public func ccmEncrypt(nonce: [UInt8], plaintext: [UInt8], aad: [UInt8] = [], tagLength: Int = 16) -> (ciphertext: [UInt8], tag: [UInt8])? {
            var ct = [UInt8](repeating: 0, count: plaintext.count)
            var tag = [UInt8](repeating: 0, count: tagLength)
            let ok = nonce.withUnsafeBytes { np in
                plaintext.withUnsafeBytes { pp in
                    aad.withUnsafeBytes { ap in
                        jp_aes_ccm_encrypt(ctx, np.bindMemory(to: UInt8.self).baseAddress, nonce.count,
                                           pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           &ct, &tag, tagLength)
                    }
                }
            }
            return ok != 0 ? (ct, tag) : nil
        }
        public func ccmDecrypt(nonce: [UInt8], ciphertext: [UInt8], aad: [UInt8] = [], tag: [UInt8]) -> [UInt8]? {
            var pt = [UInt8](repeating: 0, count: ciphertext.count)
            let ok = nonce.withUnsafeBytes { np in
                ciphertext.withUnsafeBytes { cp in
                    aad.withUnsafeBytes { ap in
                        jp_aes_ccm_decrypt(ctx, np.bindMemory(to: UInt8.self).baseAddress, nonce.count,
                                           cp.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           tag, tag.count, &pt)
                    }
                }
            }
            return ok != 0 ? pt : nil
        }

        public static func ghash(H: [UInt8], data: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 16)
            H.withUnsafeBytes { hp in
                data.withUnsafeBytes { dp in
                    jp_ghash(hp.bindMemory(to: UInt8.self).baseAddress, dp.bindMemory(to: UInt8.self).baseAddress, data.count, &out)
                }
            }
            return out
        }
    }

    // MARK: - ChaCha20-Poly1305

    public enum ChaCha20 {
        public static func block(key: [UInt8], counter: UInt32, nonce: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 64)
            key.withUnsafeBytes { jp_chacha20_block($0.bindMemory(to: UInt8.self).baseAddress, counter, nonce, &out) }
            return out
        }
        public static func xor(key: [UInt8], counter: UInt32, nonce: [UInt8], input: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: input.count)
            key.withUnsafeBytes { kp in
                input.withUnsafeBytes { ip in
                    jp_chacha20_xor(kp.bindMemory(to: UInt8.self).baseAddress, counter, nonce,
                                    ip.bindMemory(to: UInt8.self).baseAddress, &out, input.count)
                }
            }
            return out
        }
        public static func poly1305(key: [UInt8], message: [UInt8]) -> [UInt8] {
            var tag = [UInt8](repeating: 0, count: 16)
            key.withUnsafeBytes { kp in
                message.withUnsafeBytes { mp in
                    jp_poly1305_mac(kp.bindMemory(to: UInt8.self).baseAddress, mp.bindMemory(to: UInt8.self).baseAddress, message.count, &tag)
                }
            }
            return tag
        }
        public static func encrypt(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8] = []) -> (ciphertext: [UInt8], tag: [UInt8])? {
            var ct = [UInt8](repeating: 0, count: plaintext.count)
            var tag = [UInt8](repeating: 0, count: 16)
            let ok = key.withUnsafeBytes { kp in
                plaintext.withUnsafeBytes { pp in
                    aad.withUnsafeBytes { ap in
                        jp_chacha20_poly1305_encrypt(kp.bindMemory(to: UInt8.self).baseAddress, nonce,
                                                     pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                                     ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                                     &ct, &tag)
                    }
                }
            }
            return ok != 0 ? (ct, tag) : nil
        }
        public static func decrypt(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8], aad: [UInt8] = [], tag: [UInt8]) -> [UInt8]? {
            var pt = [UInt8](repeating: 0, count: ciphertext.count)
            let ok = key.withUnsafeBytes { kp in
                ciphertext.withUnsafeBytes { cp in
                    aad.withUnsafeBytes { ap in
                        jp_chacha20_poly1305_decrypt(kp.bindMemory(to: UInt8.self).baseAddress, nonce,
                                                     cp.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                                                     ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                                     tag, &pt)
                    }
                }
            }
            return ok != 0 ? pt : nil
        }
    }

    // MARK: - SM4

    public final class SM4 {
        let ctx: OpaquePointer

        public init?(key: [UInt8]) {
            guard let c = key.withUnsafeBytes({ jp_sm4_init($0.bindMemory(to: UInt8.self).baseAddress) }) else { return nil }
            self.ctx = c
        }
        deinit { jp_sm4_free(ctx) }

        public func encryptBlock(_ block: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 16)
            block.withUnsafeBytes { jp_sm4_encrypt_block(ctx, $0.bindMemory(to: UInt8.self).baseAddress, &out) }
            return out
        }
        public func decryptBlock(_ block: [UInt8]) -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 16)
            block.withUnsafeBytes { jp_sm4_decrypt_block(ctx, $0.bindMemory(to: UInt8.self).baseAddress, &out) }
            return out
        }
        public func cbcEncrypt(iv: [UInt8], plaintext: [UInt8]) -> [UInt8]? {
            var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
            let ok = plaintext.withUnsafeBytes { jp_sm4_cbc_encrypt(ctx, iv, $0.bindMemory(to: UInt8.self).baseAddress, plaintext.count, &out, &len) }
            return ok != 0 ? copyFree(&out, len) : nil
        }
        public func cbcDecrypt(iv: [UInt8], ciphertext: [UInt8]) -> [UInt8]? {
            var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
            let ok = ciphertext.withUnsafeBytes { jp_sm4_cbc_decrypt(ctx, iv, $0.bindMemory(to: UInt8.self).baseAddress, ciphertext.count, &out, &len) }
            return ok != 0 ? copyFree(&out, len) : nil
        }
        public func gcmEncrypt(iv: [UInt8], plaintext: [UInt8], aad: [UInt8] = [], tagLength: Int = 16) -> (ciphertext: [UInt8], tag: [UInt8])? {
            var ct = [UInt8](repeating: 0, count: plaintext.count)
            var tag = [UInt8](repeating: 0, count: tagLength)
            let ok = iv.withUnsafeBytes { ivp in
                plaintext.withUnsafeBytes { pp in
                    aad.withUnsafeBytes { ap in
                        jp_sm4_gcm_encrypt(ctx, ivp.bindMemory(to: UInt8.self).baseAddress, iv.count,
                                           pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           &ct, &tag, tagLength)
                    }
                }
            }
            return ok != 0 ? (ct, tag) : nil
        }
        public func gcmDecrypt(iv: [UInt8], ciphertext: [UInt8], aad: [UInt8] = [], tag: [UInt8]) -> [UInt8]? {
            var pt = [UInt8](repeating: 0, count: ciphertext.count)
            let ok = iv.withUnsafeBytes { ivp in
                ciphertext.withUnsafeBytes { cp in
                    aad.withUnsafeBytes { ap in
                        jp_sm4_gcm_decrypt(ctx, ivp.bindMemory(to: UInt8.self).baseAddress, iv.count,
                                           cp.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           tag, tag.count, &pt)
                    }
                }
            }
            return ok != 0 ? pt : nil
        }
        public func ccmEncrypt(nonce: [UInt8], plaintext: [UInt8], aad: [UInt8] = [], tagLength: Int = 16) -> (ciphertext: [UInt8], tag: [UInt8])? {
            var ct = [UInt8](repeating: 0, count: plaintext.count)
            var tag = [UInt8](repeating: 0, count: tagLength)
            let ok = nonce.withUnsafeBytes { np in
                plaintext.withUnsafeBytes { pp in
                    aad.withUnsafeBytes { ap in
                        jp_sm4_ccm_encrypt(ctx, np.bindMemory(to: UInt8.self).baseAddress, nonce.count,
                                           pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           &ct, &tag, tagLength)
                    }
                }
            }
            return ok != 0 ? (ct, tag) : nil
        }
        public func ccmDecrypt(nonce: [UInt8], ciphertext: [UInt8], aad: [UInt8] = [], tag: [UInt8]) -> [UInt8]? {
            var pt = [UInt8](repeating: 0, count: ciphertext.count)
            let ok = nonce.withUnsafeBytes { np in
                ciphertext.withUnsafeBytes { cp in
                    aad.withUnsafeBytes { ap in
                        jp_sm4_ccm_decrypt(ctx, np.bindMemory(to: UInt8.self).baseAddress, nonce.count,
                                           cp.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                                           ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                           tag, tag.count, &pt)
                    }
                }
            }
            return ok != 0 ? pt : nil
        }
    }

    // MARK: - X25519 / X448

    public enum X25519 {
        public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
            var pub = [UInt8](repeating: 0, count: 32)
            var priv = [UInt8](repeating: 0, count: 32)
            jp_x25519_generate_keypair(&pub, &priv)
            return (pub, priv)
        }
        public static func sharedSecret(privateKey: [UInt8], peerPublicKey: [UInt8]) -> [UInt8]? {
            var out = [UInt8](repeating: 0, count: 32)
            privateKey.withUnsafeBytes { p in
                peerPublicKey.withUnsafeBytes { q in
                    jp_x25519_scalar_mult(&out, p.bindMemory(to: UInt8.self).baseAddress, q.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            return out
        }
    }

    public enum X448 {
        public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
            var pub = [UInt8](repeating: 0, count: 56)
            var priv = [UInt8](repeating: 0, count: 56)
            jp_x448_generate_keypair(&pub, &priv)
            return (pub, priv)
        }
        public static func sharedSecret(privateKey: [UInt8], peerPublicKey: [UInt8]) -> [UInt8]? {
            var out = [UInt8](repeating: 0, count: 56)
            privateKey.withUnsafeBytes { p in
                peerPublicKey.withUnsafeBytes { q in
                    jp_x448_scalar_mult(&out, p.bindMemory(to: UInt8.self).baseAddress, q.bindMemory(to: UInt8.self).baseAddress)
                }
            }
            return out
        }
    }

    // MARK: - Ed25519 / Ed448

    public enum Ed25519 {
        public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
            var pub = [UInt8](repeating: 0, count: 32)
            var priv = [UInt8](repeating: 0, count: 64)
            jp_ed25519_keygen(&pub, &priv)
            return (pub, priv)
        }
        public static func derivePublicKey(seed: [UInt8]) -> [UInt8] {
            var pub = [UInt8](repeating: 0, count: 32)
            seed.withUnsafeBytes { jp_ed25519_derive_public_key($0.bindMemory(to: UInt8.self).baseAddress, &pub) }
            return pub
        }
        public static func sign(privateKey: [UInt8], message: [UInt8]) -> [UInt8] {
            var sig = [UInt8](repeating: 0, count: 64)
            privateKey.withUnsafeBytes { p in
                message.withUnsafeBytes { m in
                    jp_ed25519_sign(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, &sig)
                }
            }
            return sig
        }
        public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
            var ok: Int32 = 0
            publicKey.withUnsafeBytes { p in
                message.withUnsafeBytes { m in
                    ok = jp_ed25519_verify(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, signature)
                }
            }
            return ok != 0
        }
    }

    public enum Ed448 {
        public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
            var pub = [UInt8](repeating: 0, count: 57)
            var priv = [UInt8](repeating: 0, count: 114)
            jp_ed448_keygen(&pub, &priv)
            return (pub, priv)
        }
        public static func sign(privateKey: [UInt8], message: [UInt8]) -> [UInt8] {
            var sig = [UInt8](repeating: 0, count: 114)
            privateKey.withUnsafeBytes { p in
                message.withUnsafeBytes { m in
                    jp_ed448_sign(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, &sig)
                }
            }
            return sig
        }
        public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
            var ok: Int32 = 0
            publicKey.withUnsafeBytes { p in
                message.withUnsafeBytes { m in
                    ok = jp_ed448_verify(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, signature)
                }
            }
            return ok != 0
        }
    }

    // MARK: - ECDSA

    public enum ECDSA {
        public enum P256 {
            public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
                var pub = [UInt8](repeating: 0, count: 64)
                var priv = [UInt8](repeating: 0, count: 32)
                jp_ecdsa_p256_keygen(&pub, &priv)
                return (pub, priv)
            }
            public static func sign(privateKey: [UInt8], message: [UInt8]) -> [UInt8] {
                var sig = [UInt8](repeating: 0, count: 64)
                privateKey.withUnsafeBytes { p in
                    message.withUnsafeBytes { m in
                        jp_ecdsa_p256_sign(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, &sig)
                    }
                }
                return sig
            }
            public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
                var ok: Int32 = 0
                publicKey.withUnsafeBytes { p in
                    message.withUnsafeBytes { m in
                        ok = jp_ecdsa_p256_verify(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, signature)
                    }
                }
                return ok != 0
            }
            public static func ecdh(privateKey: [UInt8], peerPublicKey: [UInt8]) -> [UInt8]? {
                var shared = [UInt8](repeating: 0, count: 32)
                let ok = privateKey.withUnsafeBytes { p in
                    peerPublicKey.withUnsafeBytes { q in
                        jp_ecdsa_p256_ecdh(&shared, p.bindMemory(to: UInt8.self).baseAddress, q.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
                return ok != 0 ? shared : nil
            }
        }

        public enum P384 {
            public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
                var pub = [UInt8](repeating: 0, count: 96)
                var priv = [UInt8](repeating: 0, count: 48)
                jp_ecdsa_p384_keygen(&pub, &priv)
                return (pub, priv)
            }
            public static func sign(privateKey: [UInt8], message: [UInt8]) -> [UInt8] {
                var sig = [UInt8](repeating: 0, count: 96)
                privateKey.withUnsafeBytes { p in
                    message.withUnsafeBytes { m in
                        jp_ecdsa_p384_sign(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, &sig)
                    }
                }
                return sig
            }
            public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
                var ok: Int32 = 0
                publicKey.withUnsafeBytes { p in
                    message.withUnsafeBytes { m in
                        ok = jp_ecdsa_p384_verify(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, signature)
                    }
                }
                return ok != 0
            }
            public static func ecdh(privateKey: [UInt8], peerPublicKey: [UInt8]) -> [UInt8]? {
                var shared = [UInt8](repeating: 0, count: 48)
                let ok = privateKey.withUnsafeBytes { p in
                    peerPublicKey.withUnsafeBytes { q in
                        jp_ecdsa_p384_ecdh(&shared, p.bindMemory(to: UInt8.self).baseAddress, q.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
                return ok != 0 ? shared : nil
            }
        }

        public enum P521 {
            public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
                var pub = [UInt8](repeating: 0, count: 132)
                var priv = [UInt8](repeating: 0, count: 66)
                jp_ecdsa_p521_keygen(&pub, &priv)
                return (pub, priv)
            }
            public static func sign(privateKey: [UInt8], message: [UInt8]) -> [UInt8] {
                var sig = [UInt8](repeating: 0, count: 132)
                privateKey.withUnsafeBytes { p in
                    message.withUnsafeBytes { m in
                        jp_ecdsa_p521_sign(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, &sig)
                    }
                }
                return sig
            }
            public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
                var ok: Int32 = 0
                publicKey.withUnsafeBytes { p in
                    message.withUnsafeBytes { m in
                        ok = jp_ecdsa_p521_verify(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, signature)
                    }
                }
                return ok != 0
            }
        }
    }

    // MARK: - SM2

    public enum SM2 {
        public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8]) {
            var pub = [UInt8](repeating: 0, count: 64)
            var priv = [UInt8](repeating: 0, count: 32)
            jp_sm2_keygen(&pub, &priv)
            return (pub, priv)
        }
        public static func publicKey(fromPrivateKey priv: [UInt8]) -> [UInt8] {
            var pub = [UInt8](repeating: 0, count: 64)
            priv.withUnsafeBytes { jp_sm2_pub_from_priv($0.bindMemory(to: UInt8.self).baseAddress, &pub) }
            return pub
        }
        public static func sign(privateKey: [UInt8], message: [UInt8], za: [UInt8]? = nil) -> [UInt8] {
            var sig = [UInt8](repeating: 0, count: 64)
            privateKey.withUnsafeBytes { p in
                message.withUnsafeBytes { m in
                    if let za {
                        za.withUnsafeBytes { jp_sm2_sign(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, $0.bindMemory(to: UInt8.self).baseAddress, &sig) }
                    } else {
                        jp_sm2_sign(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, nil, &sig)
                    }
                }
            }
            return sig
        }
        public static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8], za: [UInt8]? = nil) -> Bool {
            var ok: Int32 = 0
            publicKey.withUnsafeBytes { p in
                message.withUnsafeBytes { m in
                    if let za {
                        ok = jp_sm2_verify(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, za, signature)
                    } else {
                        ok = jp_sm2_verify(p.bindMemory(to: UInt8.self).baseAddress, m.bindMemory(to: UInt8.self).baseAddress, message.count, nil, signature)
                    }
                }
            }
            return ok != 0
        }
        public static func computeZA(id: [UInt8], publicKey: [UInt8]) -> [UInt8] {
            var za = [UInt8](repeating: 0, count: 32)
            id.withUnsafeBytes { ip in
                publicKey.withUnsafeBytes { raw in
                    let base = raw.bindMemory(to: UInt8.self).baseAddress!
                    jp_sm2_compute_za(ip.bindMemory(to: UInt8.self).baseAddress, id.count,
                                      base, base.advanced(by: 32), &za)
                }
            }
            return za
        }
        public static func ecdh(privateKey: [UInt8], peerPublicKey: [UInt8]) -> [UInt8]? {
            var shared = [UInt8](repeating: 0, count: 32)
            let ok = privateKey.withUnsafeBytes { p in
                peerPublicKey.withUnsafeBytes { q in
                    jp_sm2_ecdh(&shared, p.bindMemory(to: UInt8.self).baseAddress, q.bindMemory(to: UInt8.self).baseAddress, peerPublicKey.count)
                }
            }
            return ok != 0 ? shared : nil
        }
    }

    // MARK: - RSA

    public enum RSA {
        /// 2048 位 RSA。公钥 512 字节（n||e），私钥 2048 字节（n,d,e,p,q,dP,dQ,qInv），
        /// 全部大端。
        public enum RSA2048 {
            public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8])? {
                var pub = jp_rsa_pub()
                var priv = jp_rsa_priv()
                guard jp_rsa2048_keygen(&pub, &priv) != 0 else { return nil }
                return (structBytes(&pub), structBytes(&priv))
            }
            public static func encrypt(publicKey: [UInt8], message: [UInt8]) -> [UInt8]? {
                var ok: Int32 = 0
                var ct = [UInt8](repeating: 0, count: 256)
                _ = withStruct(publicKey, 512) { p in
                    message.withUnsafeBytes { m in
                        ok = jp_rsa2048_encrypt(p, m.bindMemory(to: UInt8.self).baseAddress, message.count, &ct)
                    }
                }
                return ok != 0 ? ct : nil
            }
            public static func decrypt(privateKey: [UInt8], ciphertext: [UInt8]) -> [UInt8]? {
                var ok: Int32 = 0
                var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
                _ = withStruct(privateKey, 2048) { p in
                    ok = jp_rsa2048_decrypt(p, ciphertext, &out, &len)
                }
                return ok != 0 ? copyFree(&out, len) : nil
            }
            public static func oaepEncrypt(publicKey: [UInt8], message: [UInt8]) -> [UInt8]? {
                var ok: Int32 = 0
                var ct = [UInt8](repeating: 0, count: 256)
                _ = withStruct(publicKey, 512) { p in
                    message.withUnsafeBytes { m in
                        ok = jp_rsa2048_oaep_encrypt(p, m.bindMemory(to: UInt8.self).baseAddress, message.count, &ct)
                    }
                }
                return ok != 0 ? ct : nil
            }
            public static func oaepDecrypt(privateKey: [UInt8], ciphertext: [UInt8]) -> [UInt8]? {
                var ok: Int32 = 0
                var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
                _ = withStruct(privateKey, 2048) { p in
                    ok = jp_rsa2048_oaep_decrypt(p, ciphertext, &out, &len)
                }
                return ok != 0 ? copyFree(&out, len) : nil
            }
            public static func pssSign(privateKey: [UInt8], message: [UInt8], hash: PssHash = .sha256) -> [UInt8]? {
                var ok: Int32 = 0
                var sig = [UInt8](repeating: 0, count: 256)
                _ = withStruct(privateKey, 2048) { p in
                    message.withUnsafeBytes { m in
                        ok = jp_rsa2048_pss_sign(p, m.bindMemory(to: UInt8.self).baseAddress, message.count, hash.rawValue, &sig)
                    }
                }
                return ok != 0 ? sig : nil
            }
            public static func pssVerify(publicKey: [UInt8], message: [UInt8], signature: [UInt8], hash: PssHash = .sha256) -> Bool {
                var ok: Int32 = 0
                _ = withStruct(publicKey, 512) { p in
                    message.withUnsafeBytes { m in
                        ok = jp_rsa2048_pss_verify(p, m.bindMemory(to: UInt8.self).baseAddress, message.count, hash.rawValue, signature)
                    }
                }
                return ok != 0
            }
            public static func pkcs1v15Sign(privateKey: [UInt8], digest: [UInt8], digestInfoPrefix: [UInt8]) -> [UInt8]? {
                var ok: Int32 = 0
                var sig = [UInt8](repeating: 0, count: 256)
                _ = withStruct(privateKey, 2048) { p in
                    ok = jp_rsa2048_pkcs1_sign(p, digest, digest.count,
                                               digestInfoPrefix.withUnsafeBytes { $0.bindMemory(to: UInt8.self).baseAddress }, digestInfoPrefix.count, &sig)
                }
                return ok != 0 ? sig : nil
            }
            public static func pkcs1v15Verify(publicKey: [UInt8], digest: [UInt8], digestInfoPrefix: [UInt8], signature: [UInt8]) -> Bool {
                var ok: Int32 = 0
                _ = withStruct(publicKey, 512) { p in
                    ok = jp_rsa2048_pkcs1_verify(p, digest, digest.count,
                                                 digestInfoPrefix.withUnsafeBytes { $0.bindMemory(to: UInt8.self).baseAddress }, digestInfoPrefix.count, signature)
                }
                return ok != 0
            }
        }

        /// 4096 位 RSA。公钥 1024 字节，私钥 4096 字节（大端）。
        public enum RSA4096 {
            public static func keyPair() -> (publicKey: [UInt8], privateKey: [UInt8])? {
                var pub = jp_rsa4096_pub()
                var priv = jp_rsa4096_priv()
                guard jp_rsa4096_keygen(&pub, &priv) != 0 else { return nil }
                return (structBytes(&pub), structBytes(&priv))
            }
            public static func encrypt(publicKey: [UInt8], message: [UInt8]) -> [UInt8]? {
                var ok: Int32 = 0
                var ct = [UInt8](repeating: 0, count: 512)
                _ = withStruct(publicKey, 1024) { p in
                    message.withUnsafeBytes { m in
                        ok = jp_rsa4096_encrypt(p, m.bindMemory(to: UInt8.self).baseAddress, message.count, &ct)
                    }
                }
                return ok != 0 ? ct : nil
            }
            public static func decrypt(privateKey: [UInt8], ciphertext: [UInt8]) -> [UInt8]? {
                var ok: Int32 = 0
                var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
                _ = withStruct(privateKey, 4096) { p in
                    ok = jp_rsa4096_decrypt(p, ciphertext, &out, &len)
                }
                return ok != 0 ? copyFree(&out, len) : nil
            }
            public static func pssSign(privateKey: [UInt8], message: [UInt8], hash: PssHash = .sha256) -> [UInt8]? {
                var ok: Int32 = 0
                var sig = [UInt8](repeating: 0, count: 512)
                _ = withStruct(privateKey, 4096) { p in
                    message.withUnsafeBytes { m in
                        ok = jp_rsa4096_pss_sign(p, m.bindMemory(to: UInt8.self).baseAddress, message.count, hash.rawValue, &sig)
                    }
                }
                return ok != 0 ? sig : nil
            }
            public static func pssVerify(publicKey: [UInt8], message: [UInt8], signature: [UInt8], hash: PssHash = .sha256) -> Bool {
                var ok: Int32 = 0
                _ = withStruct(publicKey, 1024) { p in
                    message.withUnsafeBytes { m in
                        ok = jp_rsa4096_pss_verify(p, m.bindMemory(to: UInt8.self).baseAddress, message.count, hash.rawValue, signature)
                    }
                }
                return ok != 0
            }
        }

        public enum PssHash: Int32 {
            case sha256 = 0
            case sha384 = 1
            case sha512 = 2
        }
    }

    // MARK: - X.509

    public final class X509Certificate {
        let ptr: OpaquePointer

        public init?(der: [UInt8]) {
            guard let c = der.withUnsafeBytes({ jp_x509_cert_from_der($0.bindMemory(to: UInt8.self).baseAddress, der.count) }) else { return nil }
            self.ptr = c
        }
        public init?(pem: String) {
            guard let data = pem.data(using: .utf8) else { return nil }
            guard let c = data.withUnsafeBytes({ jp_x509_cert_from_pem($0.bindMemory(to: UInt8.self).baseAddress, data.count) }) else { return nil }
            self.ptr = c
        }
        deinit { jp_x509_cert_free(ptr) }

        public var der: [UInt8]? {
            var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
            guard jp_x509_cert_to_der(ptr, &out, &len) != 0 else { return nil }
            return copyFree(&out, len)
        }
        public var pem: String? {
            guard let s = jp_x509_cert_to_pem(ptr) else { return nil }
            defer { jp_free(s) }
            return String(cString: s)
        }
        public var commonName: String? {
            guard let s = jp_x509_common_name(ptr) else { return nil }
            defer { jp_free(s) }
            return String(cString: s)
        }
        public var issuerName: String? {
            guard let s = jp_x509_issuer_name(ptr) else { return nil }
            defer { jp_free(s) }
            return String(cString: s)
        }
        public var isValidNow: Bool { jp_x509_is_valid_now(ptr) != 0 }
        public func isValid(at unixTime: UInt64) -> Bool { jp_x509_is_valid_at(ptr, unixTime) != 0 }
        public var isCA: Bool { jp_x509_is_ca(ptr) != 0 }
        public func verifySignature(by issuer: X509Certificate) -> Bool { jp_x509_verify_signature(ptr, issuer.ptr) != 0 }
    }

    // MARK: - TLS

    public final class TLSConnection {
        let ptr: OpaquePointer

        public init() {
            self.ptr = jp_tls_conn_new()!
        }
        deinit {
            jp_tls_close(ptr)
            jp_tls_conn_free(ptr)
        }

        public func connect(host: String, port: UInt16) throws {
            var err: UnsafeMutablePointer<CChar>?
            guard jp_tls_client_connect(ptr, host, port, &err) != 0 else {
                defer { if let err { jp_free(err) } }
                throw JPSslError.operationFailed
            }
        }
        public func send(_ data: [UInt8]) throws {
            var err: UnsafeMutablePointer<CChar>?
            guard data.withUnsafeBytes({ jp_tls_send(ptr, $0.bindMemory(to: UInt8.self).baseAddress, data.count, &err) }) != 0 else {
                defer { if let err { jp_free(err) } }
                throw JPSslError.operationFailed
            }
        }
        public func recv() throws -> [UInt8] {
            var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
            var err: UnsafeMutablePointer<CChar>?
            guard jp_tls_recv(ptr, &out, &len, &err) != 0 else {
                defer { if let err { jp_free(err) } }
                throw JPSslError.operationFailed
            }
            return copyFree(&out, len)
        }
        public func close() { jp_tls_close(ptr) }
    }

    // MARK: - Base64

    public enum Base64 {
        public static func encode(_ data: [UInt8]) -> String? {
            var out: UnsafeMutablePointer<CChar>?
            guard data.withUnsafeBytes({ jp_base64_encode($0.bindMemory(to: UInt8.self).baseAddress, data.count, &out) }) != 0, let out else { return nil }
            defer { jp_free(out) }
            return String(cString: out)
        }
        public static func decode(_ text: String) -> [UInt8]? {
            let bytes = Array(text.utf8)
            var out: UnsafeMutablePointer<UInt8>?; var len: Int = 0
            guard bytes.withUnsafeBytes({ jp_base64_decode($0.bindMemory(to: CChar.self).baseAddress, bytes.count, &out, &len) }) != 0 else { return nil }
            return copyFree(&out, len)
        }
    }
}

// MARK: - 底层辅助

/// 将 C 结构体逐字节读出为 [UInt8]。
@inline(__always)
private func structBytes<T>(_ v: inout T) -> [UInt8] {
    withUnsafeBytes(of: &v) { Array($0) }
}

/// 把字节数组按字节填充进 C 结构体并调用闭包；字节不足返回 0。
/// 以原始字节存储 + 绑定指针，避免对导入的 C 结构体做 T() 默认初始化。
@inline(__always)
private func withStruct<T>(_ bytes: [UInt8], _ expectedSize: Int, _ body: (UnsafeMutablePointer<T>) -> Void) {
    guard bytes.count >= expectedSize else { return }
    var storage = [UInt8](repeating: 0, count: expectedSize)
    storage.replaceSubrange(0..<expectedSize, with: bytes.prefix(expectedSize))
    storage.withUnsafeMutableBytes { raw in
        body(raw.bindMemory(to: T.self).baseAddress!)
    }
}

/// 拷贝 malloc 缓冲到 Swift 数组并释放。
@inline(__always)
private func copyFree(_ ptr: inout UnsafeMutablePointer<UInt8>?, _ len: Int) -> [UInt8] {
    guard let p = ptr else { return [] }
    let out = Array(UnsafeBufferPointer(start: p, count: len))
    jp_free(p)
    ptr = nil
    return out
}
