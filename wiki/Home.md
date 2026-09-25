# JPSSL 维基

欢迎来到 **JPSSL** 维基。JPSSL 是一个使用 C++20 编写的高性能跨平台密码学库，同时支持 **CPU 优化**（AES-NI / AVX2 / AVX-512 / Montgomery 汇编）与可选的 **MUSA GPU 加速**（实验性）。

## 特性一览

- **对称加密**：AES-128/192/256（ECB / CBC+PKCS7 / GCM / CCM）、ChaCha20-Poly1305、SM4（ECB / CBC / GCM / CCM）
- **哈希 / MAC / KDF**：SHA-256、SHA-384/512、SHA3-256/384/512、SM3、HMAC（SHA-256/384/SM3）、HKDF（SHA-256/384/SM3）
- **非对称加密**：RSA-2048/4096（PKCS#1 v1.5 / OAEP / PSS）、ECDSA P-256、Ed25519、Ed448、X25519、X448、SM2（签名 / 验签 / 密钥交换）
- **证书**：X.509 v3 DER 编解码、自签名证书、证书链验证（RFC 5280），支持 RSA / Ed25519 / Ed448 / ECDSA / SM2 五种密钥类型
- **TLS**：TLS 1.2（RFC 5246）与 TLS 1.3（RFC 8446）完整握手、0-RTT / PSK 会话恢复、SNI 多证书管理、**RFC 8998 国密套件**（TLS_SM4_GCM_SM3 + SM2）、kTLS 内核记录层卸载（Linux）
- **DTLS**：DTLS 1.2（RFC 6347）与 DTLS 1.3（RFC 9147）标准数据报 TLS，支持记录层（epoch/seq + AEAD）、cookie、分片/重传/ACK、ECDHE（X25519 / P-256 / X448）、AES-128/256-GCM 与 ChaCha20-Poly1305；已与 OpenSSL 4（DTLS 1.2）和 wolfSSL 5.9.2（DTLS 1.2/1.3）双向互通验证
- **证书透明（CT）**：基于 RFC 6962 的国际 CT（SHA-256 + ECDSA P-256 / RSA）与国密 CT（SM3 + SM2，参考 GM/T 草案）
- **kTLS（v1.1.10）**：Linux 内核 TLS 记录层卸载——握手后把会话密钥交给内核（`TCP_ULP "tls"`），应用数据以明文直通 `send/recv`；覆盖 TLS 1.2/1.3 的 AES-GCM-128/256、ChaCha20-Poly1305、AES-CCM、SM4-GCM/CCM 套件，平台/内核不支持时优雅降级
- **工具链**：`jpssl-cert` 证书命令行工具、`jpssl-crypt` 加解密命令行工具、TLS-over-TCP socket 封装层（外部 fd 托管、非阻塞、协程 I/O、`set_skip_verify` 跳过证书认证、kTLS）、HTTPS + CT 示例
- **性能**：运行时 CPU 特性检测自动分派（AES-NI / AVX2 / AVX-512 / SHA-NI / BMI2+ADX），多数算法在基准中与 OpenSSL 持平或反超
- **平台支持**：Linux（x86_64 / ARM64）、Windows x64（MSVC）、macOS arm64、iOS 13+（arm64 XCFramework）、Android（arm64-v8a AAR）、HarmonyOS / OpenHarmony（arm64-v8a .so）

## 开始使用

- [新手引导](Beginner-Guide) — 面向新手的完整入门路线：构建、第一个程序、常见问题
- [快速开始](Getting-Started) — 环境要求、Linux / Windows 构建、安装与链接
- [构建选项与产物](Build-Options) — CMake 选项、静态/动态库、平台差异
- [命令行工具](Command-Line-Tools) — `jpssl-cert` 与 `jpssl-crypt` 用法

## API 参考

- [算法支持总览](Algorithm-Support)
- [对称加密 API](API-Symmetric) — AES、ChaCha20-Poly1305、SM4、SM4-GCM、SM4-CCM、Base64
- [哈希 / MAC / KDF API](API-Hash-MAC-KDF) — SHA-2、SHA-3、SM3、HMAC、HKDF
- [非对称加密 API](API-Asymmetric) — RSA、ECDSA、Ed25519、X25519、Ed448、X448、SM2
- [X.509 证书 API](API-X509)
- [TLS API](API-TLS) — TLS 1.2 / 1.3、0-RTT、RFC 8998 国密套件
- [TLS socket 封装层](API-TLS-Socket) — TCP/UDP、外部 fd 托管、非阻塞、协程 I/O、跳过证书认证、kTLS
- [证书透明（CT）](Certificate-Transparency)

## 进阶主题

- [MUSA GPU 加速](MUSA-GPU)
- [性能基准](Benchmarks)
- [测试与 CI](Testing)

## 技术文章

- [把吞吐量抠到极限（知乎推广文章）](知乎推广文章) — AES-GCM 解密约 7 GB/s、Base64 21 GB/s 的性能优化实战
- [jpssl 现在支持 C++11（知乎文章）](知乎文章-C++11兼容) — C++11 兼容分支说明与改造思路
- [测试方法、基准对比与互通实战（知乎文章）](知乎文章-测试对比互通) — 三层防线测试与 OpenSSL/wolfSSL 互通验证

## 相关链接

- 项目主页：<https://github.com/DaChengTechnology/JPSSL>
- 更新日志：[CHANGELOG.md](https://github.com/DaChengTechnology/JPSSL/blob/main/CHANGELOG.md)
