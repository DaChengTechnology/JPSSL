#pragma once
/**
 * ct.hpp -- 国密证书透明 (SM2 CT)
 *
 * 依据 GM/T《证书透明规范》(草案, 由零信技术牵头制定) 实现,
 * 协议框架参考 RFC 6962 Certificate Transparency:
 *   - 默克尔哈希树:   SHA-256 -> SM3 (GB/T 32905)
 *   - SCT/STH 签名:   ECDSA/RSA -> SM2 (GB/T 32918, SM3-SM2)
 *   - LogID/issuer_key_hash: SM3(SubjectPublicKeyInfo DER)
 *   - 预证书 TBS:     不含 poison 扩展 (草案定义)
 *
 * 包含:
 *   - SM3 默克尔树 (根哈希 / 审计路径 / 一致性证明)
 *   - SCT / STH 编解码与 SM2 签名
 *   - 日志条目 (MerkleTreeLeaf / PreCert)
 *   - X.509 扩展集成 (SCT 列表 / poison)
 *   - 内存版国密 CT 日志 (append-only, 可审计)
 */

#include "sm2.hpp"
#include "sm3.hpp"
#include "ecdsa.hpp"
#include "sha256.hpp"
#include "x509.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include "jpssl_optional.hpp"
#include <string>
#include <vector>

namespace jpssl {
namespace ct {

// ============================================================================
// 协议常量
// ============================================================================

constexpr size_t CT_LOG_ID_SIZE = 32;   // LogID / issuer_key_hash 长度
constexpr uint8_t CT_VERSION_V1 = 0;    // 协议版本 v1

// X.509 扩展 OID (DER 编码值, 与 x509.hpp 中 OID_* 常量同格式)
const uint8_t OID_SCT_LIST[]  = {0x2B,0x06,0x01,0x04,0x01,0xD6,0x79,0x02,0x04,0x02}; // 1.3.6.1.4.1.11129.2.4.2
const uint8_t OID_CT_POISON[] = {0x2B,0x06,0x01,0x04,0x01,0xD6,0x79,0x02,0x04,0x03}; // 1.3.6.1.4.1.11129.2.4.3
const uint8_t OID_CT_EKU[]    = {0x2B,0x06,0x01,0x04,0x01,0xD6,0x79,0x02,0x04,0x04}; // 1.3.6.1.4.1.11129.2.4.4

// DigitallySigned 中的算法标识字节。
// GM/T 草案尚未在公开文本中定稿这两个字节的取值; 本实现取 RFC 6962
// 编号体系中相邻的槽位, 便于后续按标准定稿或对方日志文档调整:
//   hash_algorithm      = 0x04 (语义为 SM3)
//   signature_algorithm = 0x04 (在 ecdsa=3 之后新增, 语义为 SM2)
constexpr uint8_t CT_HASH_ALG_SM3 = 0x04;
constexpr uint8_t CT_SIG_ALG_SM2  = 0x04;

// RFC 6962 标准（国际）CT 算法标识字节
constexpr uint8_t CT_HASH_ALG_SHA256 = 0x04;  // sha256 (RFC 6962 §3.2)
constexpr uint8_t CT_SIG_ALG_ECDSA   = 0x03;  // ecdsa (RFC 6962 §3.2)
constexpr uint8_t CT_SIG_ALG_RSA     = 0x01;  // rsa（本实现未启用）

// 日志哈希 / 签名算法策略
enum class CtHashAlg : uint8_t { SM3 = 0, SHA256 = 1 };
enum class CtSigAlg : uint8_t  { SM2 = 0, ECDSA_P256 = 1, RSA = 2 };

// SM2 签名默认用户标识符 (GB/T 32918)
constexpr char SM2_DEFAULT_ID[] = "1234567812345678";

// ============================================================================
// 枚举 (RFC 6962 TLS 风格)
// ============================================================================

// LogEntryType 上限 65535, TLS 编码为 2 字节
enum class LogEntryType : uint16_t { X509_ENTRY = 0, PRECERT_ENTRY = 1 };
enum class SignatureType : uint8_t { CERTIFICATE_TIMESTAMP = 0, TREE_HASH = 1 };
enum class MerkleLeafType : uint8_t { TIMESTAMPED_ENTRY = 0 };

// ============================================================================
// TLS 风格基础编解码
// ============================================================================

std::vector<uint8_t> encode_u16(uint16_t v);
std::vector<uint8_t> encode_u64(uint64_t v);
std::vector<uint8_t> encode_tls_vector16(const std::vector<uint8_t>& data);
std::vector<uint8_t> encode_tls_vector24(const std::vector<uint8_t>& data);

bool read_u16(const uint8_t* data, size_t len, size_t& off, uint16_t& out);
bool read_u64(const uint8_t* data, size_t len, size_t& off, uint64_t& out);
bool read_vector16(const uint8_t* data, size_t len, size_t& off, std::vector<uint8_t>& out);
bool read_vector24(const uint8_t* data, size_t len, size_t& off, std::vector<uint8_t>& out);

// ============================================================================
// SM2 标准签名 (GB/T 32918 默认用户标识符 "1234567812345678")
// ============================================================================

/// 使用标准默认 ID 计算 ZA 后对 msg 做 SM2 签名
void sm2_sign_std(const uint8_t priv[SM2_KEY_SIZE],
                  const uint8_t pub[SM2_PUB_SIZE],
                  const uint8_t* msg, size_t msg_len,
                  uint8_t sig[SM2_SIG_SIZE]);

/// 使用标准默认 ID 验证 SM2 签名
bool sm2_verify_std(const uint8_t pub[SM2_PUB_SIZE],
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t sig[SM2_SIG_SIZE]);

// ============================================================================
// SM3 默克尔哈希树 (RFC 6962 §2.1, 哈希算法换为 SM3)
// ============================================================================

/// 叶子哈希: MTH({d}) = SM3(0x00 || d)
void sm3_leaf_hash(const uint8_t* leaf, size_t leaf_len, uint8_t out[SM3_DIGEST_SIZE]);

/// 分支节点: SM3(0x01 || l || r)
void sm3_node_hash(const uint8_t l[SM3_DIGEST_SIZE],
                   const uint8_t r[SM3_DIGEST_SIZE],
                   uint8_t out[SM3_DIGEST_SIZE]);

/// 叶子哈希: SHA-256(0x00 || leaf)
void sha256_leaf_hash(const uint8_t* leaf, size_t leaf_len, uint8_t out[32]);

/// 分支节点: SHA-256(0x01 || l || r)
void sha256_node_hash(const uint8_t l[32], const uint8_t r[32], uint8_t out[32]);

using node_hash = std::array<uint8_t, SM3_DIGEST_SIZE>;

/// 计算整棵树的根哈希 (输入为叶子哈希列表; 默认 SM3, 可选 SHA-256)
node_hash merkle_root(const std::vector<node_hash>& leaf_hashes,
                      CtHashAlg alg = CtHashAlg::SM3);

/// 生成审计路径 (返回从叶到根的各兄弟节点)
std::vector<node_hash> audit_path(size_t leaf_index,
                                  const std::vector<node_hash>& leaf_hashes,
                                  CtHashAlg alg = CtHashAlg::SM3);

/// 校验审计路径
bool verify_audit_path(size_t leaf_index, size_t tree_size,
                       const node_hash& leaf_hash,
                       const std::vector<node_hash>& path,
                       const node_hash& root,
                       CtHashAlg alg = CtHashAlg::SM3);

/// 生成一致性证明 PROOF(m, D[n]) (RFC 6962 §2.1.2)
std::vector<node_hash> consistency_proof(size_t first, size_t second,
                                         const std::vector<node_hash>& leaf_hashes,
                                         CtHashAlg alg = CtHashAlg::SM3);

/// 校验一致性证明 (RFC 9162 §2.1.4.2 算法, 与 RFC 6962 相同)
bool verify_consistency(size_t first, size_t second,
                        const node_hash& first_root,
                        const node_hash& second_root,
                        const std::vector<node_hash>& proof,
                        CtHashAlg alg = CtHashAlg::SM3);

// ============================================================================
// PreCert / 日志条目
// ============================================================================

/// PreCert { issuer_key_hash[32], tbs_certificate<1..2^24-1> }
struct pre_cert {
    std::array<uint8_t, CT_LOG_ID_SIZE> issuer_key_hash{};
    std::vector<uint8_t> tbs_certificate;   // DER TBSCertificate (无 poison 扩展)
};

std::vector<uint8_t> serialize_precert(const pre_cert& pc);
jpssl::optional<pre_cert> deserialize_precert(const uint8_t* data, size_t len);

/// MerkleTreeLeaf (RFC 6962 §3.4)
struct merkle_tree_leaf {
    uint8_t version = CT_VERSION_V1;
    MerkleLeafType leaf_type = MerkleLeafType::TIMESTAMPED_ENTRY;
    uint64_t timestamp = 0;
    LogEntryType entry_type = LogEntryType::X509_ENTRY;
    std::vector<uint8_t> signed_entry;   // x509 cert DER or PreCert serialization
    std::vector<uint8_t> extensions;
};

std::vector<uint8_t> serialize_merkle_tree_leaf(const merkle_tree_leaf& leaf);
jpssl::optional<merkle_tree_leaf> deserialize_merkle_tree_leaf(const uint8_t* data, size_t len);

/// 构造 PreCert 的 signed_entry (issuer_key_hash + 24 位长度前缀 TBS)
std::vector<uint8_t> make_precert_signed_entry(const pre_cert& pc);

// ============================================================================
// SCT (Signed Certificate Timestamp)
// ============================================================================

struct signed_certificate_timestamp {
    uint8_t version = CT_VERSION_V1;
    std::array<uint8_t, CT_LOG_ID_SIZE> log_id{};
    uint64_t timestamp = 0;
    std::vector<uint8_t> extensions;
    uint8_t hash_algorithm = CT_HASH_ALG_SM3;
    uint8_t signature_algorithm = CT_SIG_ALG_SM2;
    std::vector<uint8_t> signature;
};

/// 计算 SCT 的 digitally-signed 数据 (RFC 6962 §3.2)
std::vector<uint8_t> sct_signed_data(uint64_t timestamp,
                                     LogEntryType entry_type,
                                     const std::vector<uint8_t>& signed_entry,
                                     const std::vector<uint8_t>& extensions);

std::vector<uint8_t> serialize_sct(const signed_certificate_timestamp& sct);
jpssl::optional<signed_certificate_timestamp> deserialize_sct(const uint8_t* data, size_t len);

/// 签发 SCT (SM2 签名)
signed_certificate_timestamp issue_sct(const uint8_t log_priv[SM2_KEY_SIZE],
                                       const uint8_t log_pub[SM2_PUB_SIZE],
                                       const uint8_t log_id[CT_LOG_ID_SIZE],
                                       uint64_t timestamp,
                                       LogEntryType entry_type,
                                       const std::vector<uint8_t>& signed_entry,
                                       const std::vector<uint8_t>& extensions = {});

/// 校验 SCT 签名
bool verify_sct(const signed_certificate_timestamp& sct,
                const uint8_t log_pub[SM2_PUB_SIZE],
                LogEntryType entry_type,
                const std::vector<uint8_t>& signed_entry);

/// 签发 SCT（国际标准 CT：SHA-256 哈希 + ECDSA P-256 签名, RFC 6962）
signed_certificate_timestamp issue_sct_std(const uint8_t log_priv[32],
                                           const uint8_t log_pub[64],
                                           const uint8_t log_id[CT_LOG_ID_SIZE],
                                           uint64_t timestamp,
                                           LogEntryType entry_type,
                                           const std::vector<uint8_t>& signed_entry,
                                           const std::vector<uint8_t>& extensions = {});

/// 校验 SCT 签名（国际标准 CT）
bool verify_sct_std(const signed_certificate_timestamp& sct,
                    const uint8_t log_pub[64],
                    LogEntryType entry_type,
                    const std::vector<uint8_t>& signed_entry);

/// 签发 SCT（RFC 6962：SHA-256 哈希 + RSA-2048 PKCS#1 v1.5 签名）
signed_certificate_timestamp issue_sct_rsa(const rsa_crt_key& log_priv,
                                           const uint8_t log_id[CT_LOG_ID_SIZE],
                                           uint64_t timestamp,
                                           LogEntryType entry_type,
                                           const std::vector<uint8_t>& signed_entry,
                                           const std::vector<uint8_t>& extensions = {});

/// 校验 SCT 签名（RFC 6962 RSA）
bool verify_sct_rsa(const signed_certificate_timestamp& sct,
                    const rsa_public_key& log_pub,
                    LogEntryType entry_type,
                    const std::vector<uint8_t>& signed_entry);

// ============================================================================
// STH (Signed Tree Head)
// ============================================================================

struct signed_tree_head {
    uint8_t version = CT_VERSION_V1;
    uint64_t timestamp = 0;
    uint64_t tree_size = 0;
    node_hash root_hash{};
    uint8_t hash_algorithm = CT_HASH_ALG_SM3;
    uint8_t signature_algorithm = CT_SIG_ALG_SM2;
    std::vector<uint8_t> signature;
};

std::vector<uint8_t> sth_signed_data(const signed_tree_head& sth);
std::vector<uint8_t> serialize_sth(const signed_tree_head& sth);

signed_tree_head sign_sth(const uint8_t log_priv[SM2_KEY_SIZE],
                          const uint8_t log_pub[SM2_PUB_SIZE],
                          uint64_t timestamp, uint64_t tree_size,
                          const node_hash& root_hash);

bool verify_sth(const signed_tree_head& sth, const uint8_t log_pub[SM2_PUB_SIZE]);

/// 签名 STH（国际标准 CT）
signed_tree_head sign_sth_std(const uint8_t log_priv[32],
                              const uint8_t log_pub[64],
                              uint64_t timestamp, uint64_t tree_size,
                              const node_hash& root_hash);

/// 校验 STH 签名（国际标准 CT）
bool verify_sth_std(const signed_tree_head& sth, const uint8_t log_pub[64]);

/// 签名 STH（RFC 6962 RSA）
signed_tree_head sign_sth_rsa(const rsa_crt_key& log_priv,
                              uint64_t timestamp, uint64_t tree_size,
                              const node_hash& root_hash);

/// 校验 STH 签名（RFC 6962 RSA）
bool verify_sth_rsa(const signed_tree_head& sth, const rsa_public_key& log_pub);

// ============================================================================
// X.509 集成
// ============================================================================

/// LogID = SM3(日志公钥证书的 SubjectPublicKeyInfo DER)
node_hash compute_log_id(const x509::x509_cert& log_cert);

/// LogID = SHA-256(日志公钥证书的 SubjectPublicKeyInfo DER)（RFC 6962）
node_hash compute_log_id_std(const x509::x509_cert& log_cert);

/// 证书链的 TLS 序列化 (3 字节长度前缀, RFC 6962 ASN.1Cert<1..2^24-1>)
std::vector<uint8_t> serialize_cert_chain(const std::vector<std::vector<uint8_t>>& chain);

/// 给预证书签发最终证书: 去掉 poison 扩展、嵌入 SCT 列表扩展, 由 CA 重新签名
/// @return 最终用户证书 (x509_cert, 可用 to_der() 输出)
x509::x509_cert finalize_precert(const x509::x509_cert& precert,
                                 const std::vector<signed_certificate_timestamp>& scts,
                                 x509::KeyType sign_key_type,
                                 const uint8_t* ca_priv, size_t ca_priv_len);

/// 从最终证书重建预证书 TBS: 解析最终证书, 删除 SCT 列表扩展
/// @return DER TBSCertificate (不含签名), 失败时返回 nullopt
jpssl::optional<std::vector<uint8_t>> precert_tbs_from_final(const std::vector<uint8_t>& final_cert_der);

/// 编码 SCT 列表扩展的 extnValue (ASN.1 OCTET STRING 包裹 TLS 列表)
std::vector<uint8_t> encode_sct_list_extn(const std::vector<signed_certificate_timestamp>& scts);

/// 解码 SCT 列表扩展的 extnValue
jpssl::optional<std::vector<signed_certificate_timestamp>>
decode_sct_list_extn(const std::vector<uint8_t>& extn_value);

/// 从最终证书 DER 中读取并解码全部 SCT
jpssl::optional<std::vector<signed_certificate_timestamp>>
scts_from_cert(const std::vector<uint8_t>& cert_der);

// ============================================================================
// 内存版 CT 日志 (append-only, 可审计; 支持国密 SM3+SM2 与国际 SHA-256+ECDSA)
// ============================================================================

class ct_log {
public:
    using clock_fn = uint64_t (*)();

    /// 国密日志（默认 SM3 哈希 + SM2 签名；兼容旧 sm2_ct_log 用法）
    ct_log(const uint8_t log_priv[32],
           const uint8_t log_pub[64],
           clock_fn now_fn = nullptr);

    /// 指定算法：CtHashAlg::SHA256 + CtSigAlg::ECDSA_P256 即国际标准 CT (RFC 6962)
    ct_log(CtHashAlg hash_alg, CtSigAlg sig_alg,
           const uint8_t log_priv[32],
           const uint8_t log_pub[64],
           clock_fn now_fn = nullptr);

    /// RSA 日志（RFC 6962：SHA-256 + RSA-2048 PKCS#1 v1.5）
    ct_log(const rsa_crt_key& log_priv, const rsa_public_key& log_pub,
           clock_fn now_fn = nullptr);

    CtHashAlg hash_alg() const { return hash_alg_; }
    CtSigAlg sig_alg() const { return sig_alg_; }
    const node_hash& log_id() const { return log_id_; }

    /// 接受某个 CA 根证书 (DER)
    void accept_root(const std::vector<uint8_t>& root_der);
    /// 清空已接受的根
    void clear_roots();

    /// add-chain: 提交最终证书链 (leaf, ..., root), 返回 SCT
    jpssl::optional<signed_certificate_timestamp>
    add_chain(const std::vector<std::vector<uint8_t>>& chain, std::string* error = nullptr);

    /// add-pre-chain: 提交预证书链, 返回 SCT
    jpssl::optional<signed_certificate_timestamp>
    add_pre_chain(const std::vector<std::vector<uint8_t>>& chain, std::string* error = nullptr);

    /// get-sth: 当前签名树头
    signed_tree_head get_sth();

    /// get-sth-consistency
    std::vector<node_hash> get_sth_consistency(uint64_t first, uint64_t second) const;

    /// get-proof-by-hash: 按叶哈希取审计路径
    bool get_proof_by_hash(const node_hash& leaf_hash, uint64_t tree_size,
                           uint64_t* leaf_index, std::vector<node_hash>* path) const;

    /// get-entries: 返回 [start, end] 条目 (leaf_input, extra_data)
    bool get_entries(uint64_t start, uint64_t end,
                     std::vector<std::vector<uint8_t>>* leaf_inputs,
                     std::vector<std::vector<uint8_t>>* extra_datas) const;

    size_t tree_size() const { return leaf_hashes_.size(); }
    const node_hash& leaf_hash_at(size_t i) const { return leaf_hashes_[i]; }

private:
    jpssl::optional<signed_certificate_timestamp>
    append_entry(merkle_tree_leaf leaf, std::vector<uint8_t> extra_data,
                 std::string* error);

    bool chain_ok(const std::vector<std::vector<uint8_t>>& chain,
                  bool expect_precert, std::string* error) const;

    uint64_t now() const { return now_fn_ ? now_fn_() : (uint64_t)time(nullptr); }

    CtHashAlg hash_alg_ = CtHashAlg::SM3;
    CtSigAlg sig_alg_ = CtSigAlg::SM2;
    uint8_t log_priv_[32]{};
    uint8_t log_pub_[64]{};
    node_hash log_id_{};
    jpssl::optional<rsa_crt_key> rsa_priv_;    // sig_alg_ == RSA 时有效
    jpssl::optional<rsa_public_key> rsa_pub_;
    clock_fn now_fn_ = nullptr;
    uint64_t last_sth_time_ = 0;
    uint64_t last_entry_time_ = 0;
    std::vector<std::vector<uint8_t>> roots_;          // 接受的根证书 DER
    std::vector<merkle_tree_leaf> entries_;
    std::vector<std::vector<uint8_t>> extra_datas_;
    std::vector<node_hash> leaf_hashes_;
};

/// 兼容旧名：ct_log 默认即国密（SM3 + SM2）
using sm2_ct_log = ct_log;

} // namespace ct
} // namespace jpssl
