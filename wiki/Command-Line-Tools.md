# 命令行工具

构建后生成两个命令行工具，`make install` 后安装到 `bin/` 目录：

| 工具 | 说明 | 源文件 |
|------|------|--------|
| `jpssl-cert` | X.509 v3 证书生成 / 查看 / 验证 | `src/cmd/jpssl_cert.cpp` |
| `jpssl-crypt` | 加密 / 解密 / 哈希 / HMAC / Base64 / 随机数 | `src/cmd/jpssl_crypt.cpp` |

## jpssl-cert — 证书工具

```bash
# 生成自签名 X.509 v3 证书 + 私钥 (有效期默认 365 天)
# 默认输出到 ~/.ssh/cert.der 与 ~/.ssh/key.bin (目录自动创建, 私钥权限 0600)
jpssl-cert gen --cn example.com --key-type ed25519
# 支持的密钥类型: ed25519 | ecdsa | sm2 | rsa2048 | ed448
# 用 --days 指定有效期 (gen / tlsgen 均支持, 默认 365 天)
# 用 --out / --key-out 指定其他位置 (支持 ~ 展开)
jpssl-cert gen --cn example.com --key-type ed25519 --days 90 --out ~/certs/cert.der --key-out ~/certs/key.bin
# 私钥默认输出为 PKCS#8 PEM（-----BEGIN PRIVATE KEY-----，与 openssl genpkey 一致；
# Ed25519/Ed448 为 RFC 8410，ECDSA/SM2 内嵌 SEC1，RSA 内嵌完整 PKCS#1）；
# 需要二进制时加 --key-format der

# 查看证书信息 (支持 DER 或 PEM)
jpssl-cert info --cert cert.der
jpssl-cert info --cert cert.pem

# 查看私钥 (PKCS#8 / PKCS#1 / SEC1 / [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) PEM)
jpssl-cert key --key key.pem
# 查看加密私钥 (PBES2, 需 --pass 密码)
jpssl-cert key --key encrypted.pem --pass your-password

# 查看 CSR (PKCS#10 PEM)
jpssl-cert csr --csr request.csr

# 验证证书链 (leaf → root) (支持 DER 或 PEM)
jpssl-cert verify --cert leaf.der --ca root.der
# 多级链: --ca 可多次指定中间 CA
jpssl-cert verify --cert leaf.der --ca intermediate.der --ca root.der

# 通过 TLS API 生成证书（等价于 tls_make_x509_self_signed）
jpssl-cert tlsgen --cn example.com --key-type ecdsa
# 指定有效期 10 年
jpssl-cert tlsgen --cn example.com --key-type ecdsa --days 3650 --out cert.der --key-out key.bin
```

## jpssl-crypt — 加密 / 哈希工具

```bash
# AES-256-GCM 加密（[FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) + [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38d/final)，输出格式: IV || 密文 || Tag）
jpssl-crypt encrypt --algo aes256gcm --key <hex-key> --in plain.txt --out cipher.bin

# ChaCha20-Poly1305 加密（[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)）
jpssl-crypt encrypt --algo chacha20 --key <hex-key> --in plain.txt --out cipher.bin

# 解密 (自动从文件提取 IV 和 Tag)
jpssl-crypt decrypt --algo aes256gcm --key <hex-key> --in cipher.bin --out plain.txt

# 哈希
jpssl-crypt hash --algo sha1   --in file.txt     # SHA-1 (20 bytes)
jpssl-crypt hash --algo sha256 --in file.txt
jpssl-crypt hash --algo sm3   --in file.txt     # 国密 SM3

# HMAC（[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) / [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final)）
jpssl-crypt hmac --algo sha256 --key <hex-key> --in file.txt

# Base64 编码 / 解码（[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)）
jpssl-crypt b64encode --in file.bin --out file.b64
jpssl-crypt b64decode --in file.b64 --out file.bin

# 生成随机字节 (十六进制输出)
jpssl-crypt rand 32
```

支持的算法：

- **加密**：`aes256gcm`（AES-256-GCM AEAD）、`chacha20`（ChaCha20-Poly1305 AEAD）
- **哈希**：`sha1`、`sha256`、`sha512`、`sha3-256`、`sha3-512`、`sm3`
- **HMAC**：`sha256`、`sha384`、`sm3`
- **Base64**：`b64encode`（二进制 → [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) 文本）、`b64decode`（文本 → 二进制）

密钥、IV、Tag 均以十六进制字符串传入，AAD 认证数据可用 `--aad <hex>` 指定。

> `b64decode` 容忍文本文件中的空白字符（行尾换行、空格、tab），解码失败时返回非零退出码；未指定 `--out` 时输出到 stdout（编码输出带换行，解码输出原始二进制）。
