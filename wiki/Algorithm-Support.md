# 算法支持总览

| 算法 | 模式 | CPU 加速 | GPU 加速 |
|------|------|----------|----------|
| **AES-128/256** | ECB、CBC+PKCS7、GCM、CCM | AES-NI（约 5 GB/s）、AVX2/AVX512 GCM | ECB kernel（实验性） |
| **GHASH / GF(2^128)** | GCM 认证原语（一次性/增量/GCM 完整哈希） | PCLMULQDQ | — |
| **ChaCha20-Poly1305** | 流加密、AEAD | AVX2 / AVX-512 多块并行 | Keystream kernel（实验性） |
| **RSA 2048/4096** | PKCS#1 v1.5、OAEP、PSS | Montgomery CIOS + MULX 汇编、批量 AVX2/AVX512 | 批量模幂（实验性） |
| **SHA-1** | 哈希（FIPS 180-4） | AVX2 8 路 / AVX-512 16 路多缓冲批量哈希 | — |
| **SHA-256** | 哈希 | SHA-NI | — |
| **SHA-384/512** | 哈希（FIPS 180-4） | SSE4.1 消息调度 | GPU kernel（实验性） |
| **SHA3-256/384/512** | 哈希（FIPS 202，Keccak） | — | — |
| **HMAC-SHA256/SHA384/SM3** | MAC | — | — |
| **HKDF-SHA256/SHA384/SM3** | TLS 1.3 密钥派生 | — | — |
| **X25519** | ECDH 密钥交换 | AVX-512 | — |
| **X448** | ECDH 密钥交换 | AVX2 / AVX-512 | — |
| **Ed25519** | 数字签名（EdDSA） | AVX-512、批量验签 | — |
| **Ed448** | 数字签名（EdDSA） | AVX2 / AVX-512、批量验签 | — |
| **ECDSA P-256/P-384/P-521** | 数字签名与 ECDHE（secp256r1/secp384r1/secp521r1） | — | — |
| **SM2** | 数字签名 / 密钥交换（sm2p256v1，[GM/T 0003](https://www.oscca.gov.cn/)） | Montgomery(CIOS) + wNAF-5 标量乘 + Shamir 双标量 | — |
| **SM3** | 密码杂凑（256-bit，[GM/T 0004](https://www.oscca.gov.cn/)） | MSVC x64 MASM 标量汇编 | — |
| **SM4** | 分组密码（128-bit，[GM/T 0002](https://www.oscca.gov.cn/)），ECB / CBC / GCM / CCM | T 表加速标量核心，SM4-GCM 使用 PCLMULQDQ 快速 GHASH | — |
| **X.509 v3** | 证书 DER / PEM 编解码（[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)）、私钥读取（PKCS#8 / PKCS#1 / SEC1 / 加密 PBES2）、CSR（PKCS#10）、自签名、证书链、SAN / KeyUsage / BasicConstraints | — | — |
| **TLS 1.2/1.3** | 完整握手、密码套件协商、ECDHE/RSA、0-RTT、[RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) 国密套件 | AVX2/AVX512 GCM | — |
| **Base64** | [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) 编解码 | AVX2（约 21-22 GB/s 编码）、AVX-512（约 17 GB/s 解码） | — |
| **证书透明（CT）** | [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) 国际（SHA-256 + ECDSA P-256 / RSA）+ 国密（SM3 + SM2） | — | — |

## TLS 密码套件

### TLS 1.3

- AES-128-GCM / AES-256-GCM（SHA-256 / SHA-384）
- ChaCha20-Poly1305（SHA-256）
- AES-128-CCM
- **[RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) 国密**：`TLS_SM4_GCM_SM3` + SM2 签名
- 证书签名算法：Ed25519、Ed448、ECDSA P-256/P-384/P-521、RSA-2048/4096（SHA-256/384/512）、SM2
- 密钥交换：ECDHE（X25519 / P-256 / P-384 / P-521）、X448（基于前向保密 ECDHE）
- 会话恢复：PSK / NewSessionTicket / 0-RTT early data

### TLS 1.2（[RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)）

| 套件 | 密钥交换 | 加密 | 哈希 |
|------|---------|------|------|
| `0xC02C` | ECDHE-ECDSA | AES-256-GCM | SHA-384 |
| `0xC030` | ECDHE-RSA | AES-256-GCM | SHA-384 |
| `0xC02B` | ECDHE-ECDSA | AES-128-GCM | SHA-256 |
| `0xC02F` | ECDHE-RSA | AES-128-GCM | SHA-256 |
| `0xCCA9` | ECDHE-ECDSA | ChaCha20-Poly1305 | SHA-256 |
| `0xCCA8` | ECDHE-RSA | ChaCha20-Poly1305 | SHA-256 |
| `0x009C` | RSA | AES-128-GCM | SHA-256 |
| `0x009D` | RSA | AES-256-GCM | SHA-384 |

## 标准合规

- AES：[FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final)；GCM：[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38d/final)；CCM：[NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38c/final)；ChaCha20-Poly1305：[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)
- SHA-1 / SHA-2：[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/final)；SHA-3：[FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)；HMAC：[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) / [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final)；HKDF：[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
- RSA：PKCS#1 v1.5 / OAEP / PSS（[RFC 8017](https://www.rfc-editor.org/rfc/rfc8017)）
- Ed25519 / Ed448：RFC 8032（[Ed25519](https://www.rfc-editor.org/rfc/rfc8032)）；X25519 / X448：[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- ECDSA：secp256r1 / secp384r1 / secp521r1（[FIPS 186-4](https://csrc.nist.gov/pubs/fips/186-4/final)）
- X.509：[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)
- TLS 1.2：[RFC 5246](https://www.rfc-editor.org/rfc/rfc5246)；TLS 1.3：[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)；国密 TLS：[RFC 8998](https://www.rfc-editor.org/rfc/rfc8998)
- CT：[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)（国际）/ [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) 一致性证明（验证按 §2.1.4.2）/ GM/T 草案（国密）
- 国密：GM/T 0002-2012（SM4）、GM/T 0003-2012（SM2）、GM/T 0004-2012（SM3），详见 [RFC 8998 国密套件](https://www.rfc-editor.org/rfc/rfc8998) 与 [GM/T 标准说明](https://www.oscca.gov.cn/)
