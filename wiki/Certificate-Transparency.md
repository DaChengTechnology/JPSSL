# 证书透明（Certificate Transparency）

头文件：`include/ct.hpp`，源文件 `src/ct.cpp`。

JPSSL 提供两套证书透明实现：

- **国际标准**：基于 [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)，SHA-256 默克尔树 + ECDSA P-256（或 RSA-2048 PKCS#1 v1.5）签名；
- **国密**：基于 [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) 框架、以 SM2/SM3 替代 ECDSA/SHA-256（参考 GM/T《证书透明规范》草案）。

## 核心概念与功能

### 默克尔树

- 叶哈希 / 节点哈希：`sm3_leaf_hash` / `sm3_node_hash`（SM3 变体），`sha256_leaf_hash` / `sha256_node_hash`（SHA-256 变体）
- 树根：`merkle_root(leaf_hashes)`
- 审计路径：`audit_path(leaf_index, tree_size)` + `verify_audit_path(...)`
- 一致性证明：`consistency_proof(first, second)` + `verify_consistency(first, second, ...)`（按 [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) §2.1.4.2 实现）

### TLS 风格编解码

- `pre_cert` / `merkle_tree_leaf` / SCT / STH 的序列化与反序列化（`serialize_precert` / `deserialize_precert` 等）
- LogID：国际算法 `compute_log_id_std`（SHA-256(SPKI)）；国密算法按草案计算
- X.509 集成：precert poison / SCT list 扩展、`finalize_precert`

### 内存日志

- `sm2_ct_log(priv, pub)`：国密日志（SM3 默克尔树 + SM2 签名）
- `ct_log(CtHashAlg::SHA256, CtSigAlg::ECDSA_P256, priv, pub)`：国际日志（SHA-256 默克尔树 + ECDSA P-256 签名）
- `ct_log(rsa_crt_key, rsa_public_key)`：RSA 日志（SHA-256 + RSA-2048 PKCS#1 v1.5）

日志接口（[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) 风格）：

```cpp
add_pre_chain / add_chain        // 提交证书或预证书
get_sth                          // 获取 Signed Tree Head
get_proof_by_hash                // 包含性证明
get_entries                      // 按序号获取日志条目
get_sth_consistency              // 一致性证明
```

## 签发与验证

```cpp
// 国际标准（ECDSA P-256）
issue_sct_std(...) / verify_sct_std(...)
sign_sth_std(...)   / verify_sth_std(...)

// 国密（SM2 + SM3）
issue_sct(...)     / verify_sct(...)       // 或 sm2_ct_log 内置方法
sign_sth(...)      / verify_sth(...)

// RSA
issue_sct_rsa(...) / verify_sct_rsa(...)
sign_sth_rsa(...)  / verify_sth_rsa(...)
```

## 注意

> `DigitallySigned` 中的算法字节当前为国密草案占位值（`CT_HASH_ALG_SM3 = 0x04`、`CT_SIG_ALG_SM2 = 0x04`），草案未定稿，与外部国密 CT 日志互操作前需核对字节值。

## HTTPS + CT 示例

`examples/https/` 提供 HTTPS 服务器与客户端示例，基于 [TLS socket 封装层](API-TLS-Socket)：

```bash
# 终端 1：启动 HTTPS + CT 服务器（默认 8443）
./https_server 8443

# 终端 2：客户端执行证书链 / SCT / STH / 包含性证明审计
./https_client 127.0.0.1 8443
```

服务器内嵌内存 CT 日志，为 ECDSA 服务器证书签发 SCT 并暴露 `/ct/cert`、`/ct/precert`、`/ct/ca`、`/ct/log-key`、`/ct/sth`、`/ct/proof` 等审计端点；客户端通过 TLS 1.3 连接完成全部 CT 校验。
