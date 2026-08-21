# X.509 v3 证书 API（[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)）

头文件：`include/x509.hpp`，命名空间 `jpssl::x509`。

提供完整的 X.509 v3 证书 **DER 编解码**、**自签名证书生成**和**证书链验证**。支持 RSA-2048/4096、Ed25519、Ed448、ECDSA P-256、SM2 五种密钥类型。

## 1. 生成自签名证书

```cpp
#include "x509.hpp"
using namespace jpssl::x509;

// 生成 Ed25519 密钥
uint8_t pub[32], priv[64];
ed25519_keygen(pub, priv);

// 构建并签名自签名证书
x509_builder builder;
DistinguishedName dn;
dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + 3), "example.com"});
builder.set_subject(dn).set_issuer(dn);                    // 自签名: subject == issuer

uint8_t serial[8] = {0x01, 0x02, 0x03, 0x04};
builder.set_serial(serial, 8);

uint64_t now = (uint64_t)time(nullptr);
builder.set_validity(now, now + 365ULL * 86400);           // 有效期 365 天

builder.set_key(KeyType::Ed25519, pub, 32);                // 公钥
builder.set_ca(false);                                     // 叶子证书 (CA=false)
builder.set_key_usage(KU_DIGITAL_SIGNATURE);               // KeyUsage 扩展
builder.set_server_auth();                                 // EKU: serverAuth
builder.add_san_dns("example.com");                        // SAN: DNS 名称
builder.add_san_dns("www.example.com");

auto cert = builder.build_and_sign(KeyType::Ed25519, priv, 64); // 私钥签名

// 编码为 DER 字节
std::vector<uint8_t> der = cert.to_der();
```

## 2. 解析 DER / PEM 证书

```cpp
// 从 DER 字节解析
auto parsed = x509_cert::from_der(der);
// 从 PEM 文本解析 (-----BEGIN CERTIFICATE-----)
auto parsed = x509_cert::from_pem(pem_string);
// 证书编码为 PEM
std::string pem = parsed->to_pem();

if (parsed) {
    std::string cn = parsed->common_name();        // 获取 subject CN
    std::string issuer = parsed->issuer_name();    // 获取 issuer CN
    bool is_ca = parsed->is_ca();                  // 是否 CA 证书
    bool valid = parsed->is_valid_now();           // 是否在有效期内
    auto dns = parsed->dns_names();                // SAN DNS 名称列表
    KeyType kt = parsed->key_type;                 // 密钥类型
}
```

`x509_cert` 还提供：

- `raw_extensions`：原始扩展保留，未知扩展在解析 / 编码时原样保留（证书透明的 SCT list / poison 扩展依赖此能力）
- 序列号、签名算法、SPKI、时间字段等访问器

## 3. 读取私钥 / CSR（PEM / DER）

```cpp
// 私钥读取: 自动识别 PKCS#8 / PKCS#1 RSA / SEC1 EC / [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) (Ed25519/Ed448)
//   -----BEGIN PRIVATE KEY----- / RSA PRIVATE KEY / EC PRIVATE KEY
//   -----BEGIN ED25519 PRIVATE KEY----- / ED448 PRIVATE KEY-----
auto key = private_key::from_pem(key_pem);
if (key) {
    KeyType kt = key->key_type;       // 密钥类型
    auto& priv = key->priv;           // 私钥原始字节 (与 x509_builder::build_and_sign 兼容)
    auto& pub  = key->pub;            // 公钥原始字节 (解析时从密钥中恢复)
}
// 支持 DER 输入: private_key::from_der(...)

// 加密私钥读取 (PBES2, -----BEGIN ENCRYPTED PRIVATE KEY-----)
//   PBKDF2-HMAC-SHA256 + AES-128/256-CBC ([RFC 8018](https://www.rfc-editor.org/rfc/rfc8018))
auto enc_key = private_key::from_pem_encrypted(enc_pem, "password");

// CSR 读取 (PKCS#10, -----BEGIN CERTIFICATE REQUEST-----)
auto req = csr::from_pem(csr_pem);
if (req) {
    auto& subject = req->subject;     // DistinguishedName
    KeyType kt = req->key_type;       // 公钥类型
    auto& pub = req->public_key;      // 公钥原始字节
    auto& sig = req->signature;       // 签名原始字节
    auto& tbs = req->tbs_raw;         // CertificationRequestInfo 原始字节 (供验签)
}
```

私钥输出格式与库内 `x509_builder::build_and_sign` 完全兼容（RSA=d、Ed25519=seed‖pub、Ed448=seed、EC/SM2=scalar），解析出的密钥可直接用于证书签发。

## 4. 证书链验证

```cpp
// 构建根 CA（自签名, CA=true, KeyCertSign）
x509_builder root_builder;
root_builder.set_ca(true, 0);                                // pathLen=0
root_builder.set_key_usage(KU_KEY_CERT_SIGN);
auto root = root_builder.build_and_sign(KeyType::Ed25519, root_priv, 64);

// 叶子证书由根 CA 签发（issuer=root, 用根私钥签名）
x509_builder leaf_builder;
leaf_builder.set_issuer(root_dn);
auto leaf = leaf_builder.build_and_sign(KeyType::Ed25519, root_priv, 64);

// 验证证书链: leaf → root
std::vector<x509_cert> chain = {leaf, root};
auto result = x509_verify_chain(chain, now);
if (result.success) {
    // 链有效: 签名正确、有效期未过期、根证书是 CA
} else {
    std::string err = result.error;   // 失败原因
}
```

验证内容包括：签名正确性、有效期、CA 属性（BasicConstraints）、KeyUsage（KeyCertSign）、路径长度（pathLen）约束。

### OpenSSL 互操作

证书签名验证兼容 OpenSSL 3.0 生成的证书：

- **签名格式**：同时接受定长 raw `r‖s` 与本库自产格式，以及 DER 编码的 `ECDSA-Sig-Value`（`SEQUENCE { INTEGER r, INTEGER s }`，OpenSSL 默认输出，支持长短格式长度）。
- **SM2**：验证时按国密标准计算 `e = SM3(ZA ‖ TBS)`（单层哈希），ZA 依次尝试空用户 ID（OpenSSL 3.0 `x509` 生成行为）与国密标准默认 ID `"1234567812345678"`（[GB/T 32918.5 / GM/T 0003](https://www.oscca.gov.cn/)），兼容主流实现；本库签发的 SM2 证书与 OpenSSL 互验通过。
- **ECDSA P-256/P-384/P-521**：`ecdsa_pXXX_sign/verify` 内部自带哈希，签名 / 验证直接对 TBS 字节进行，避免双重哈希；P-384/P-521 曲线 OID 使用标准值 `1.3.132.0.34/35`。

双向互操作已实测：OpenSSL 签发的 SM2 / P-256 / P-384 / P-521 证书本库可验证，本库签发的证书 `openssl verify` 通过。

## 5. TLS 集成

```cpp
#include "tls.hpp"
using namespace jpssl::tls;

// 从 tls_certificate 生成 X.509 DER 自签名证书
std::vector<uint8_t> der = tls_make_x509_self_signed(*tls_cert);

// 密钥类型映射
x509::KeyType kt = tls_sig_alg_to_key_type(cert->sig_alg);
```

TLS 握手时若 `tls_certificate::cert_data` 为空，会自动生成 X.509 v3 DER 证书并发送给对端（`tls13_make_certificate` / `tls12_make_certificate` 均支持）。

## 支持的关键类型

- `KeyType`：`RSA2048`、`RSA4096`、`Ed25519`、`Ed448`、`ECDSA_P256`、`SM2`
- `x509_builder`：链式设置 subject / issuer / serial / validity / key / CA / KeyUsage / EKU / SAN
- `x509_cert`：`from_der` / `from_pem` 解析、`to_der` / `to_pem` 编码、属性访问器
- `private_key`：`from_der` / `from_pem` / `from_pem_encrypted`（PKCS#8/PKCS#1/SEC1/[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)/加密 PEM）
- `csr`：`from_der` / `from_pem`（PKCS#10）
- `x509_verify_chain`：证书链验证结果 `{ success, error }`

## 命令行工具

也可以直接用 [jpssl-cert](Command-Line-Tools) 在命令行生成、查看和验证证书。
