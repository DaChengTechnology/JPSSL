/**
 * ct.cpp -- SM2 Certificate Transparency (GM/T draft, RFC 6962 frame)
 *
 * Implements:
 *   - TLS-style encoding helpers
 *   - SM2 standard signatures (GB/T 32918, default ID "1234567812345678")
 *   - SM3 Merkle tree: root / audit path / consistency proof
 *   - PreCert, MerkleTreeLeaf, SCT, STH serialization & signing
 *   - X.509 integration: LogID, finalize_precert, SCT list extension
 *   - In-memory append-only SM2 CT log
 */
#include "ct.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace jpssl::ct {

namespace {

// SHA-256 DigestInfo 前缀 (RFC 8017 §9.2, 不含 32 字节 digest)
const uint8_t k_sha256_digest_info[] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,
    0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,
    0x00,0x04,0x20
};

inline void append(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

inline bool oid_is(const std::vector<uint8_t>& oid, const uint8_t* raw, size_t raw_len) {
    return oid.size() == raw_len && memcmp(oid.data(), raw, raw_len) == 0;
}

// Read a DER TLV's total length (tag + length + value) starting at `off`.
bool tlv_total_len(const uint8_t* data, size_t len, size_t off, size_t& total) {
    if (off >= len) return false;
    size_t pos = off + 1;
    if (pos >= len) return false;
    uint8_t first = data[pos++];
    size_t vlen;
    if (first < 0x80) {
        vlen = first;
    } else {
        size_t nb = first & 0x7F;
        if (nb == 0 || nb > 4 || pos + nb > len) return false;
        vlen = 0;
        for (size_t i = 0; i < nb; ++i) vlen = (vlen << 8) | data[pos++];
    }
    if (pos + vlen > len) return false;
    total = pos + vlen - off;
    return true;
}

bool read_u24(const uint8_t* data, size_t len, size_t& off, uint32_t& out) {
    if (off + 3 > len) return false;
    out = ((uint32_t)data[off] << 16) | ((uint32_t)data[off + 1] << 8) | data[off + 2];
    off += 3;
    return true;
}

// ---- Merkle tree internals (hash-algorithm agnostic) ----

struct hash_ops {
    void (*leaf)(const uint8_t*, size_t, uint8_t[32]);
    void (*node)(const uint8_t[32], const uint8_t[32], uint8_t[32]);
    node_hash (*empty)();
};

node_hash sm3_empty_hash() {
    node_hash h{};
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_final(&ctx, h.data());
    return h;
}

node_hash sha256_empty_hash() {
    node_hash h{};
    sha256(nullptr, 0, h.data());
    return h;
}

const hash_ops& ops_for(CtHashAlg alg) {
    static const hash_ops k_sm3 = { sm3_leaf_hash, sm3_node_hash, sm3_empty_hash };
    static const hash_ops k_sha256 = { sha256_leaf_hash, sha256_node_hash, sha256_empty_hash };
    return alg == CtHashAlg::SHA256 ? k_sha256 : k_sm3;
}

node_hash node_hash_of(const node_hash& l, const node_hash& r, const hash_ops& ops) {
    node_hash out;
    ops.node(l.data(), r.data(), out.data());
    return out;
}

// Largest power of two strictly less than n.
size_t pow2_floor(size_t n) {
    size_t k = 1;
    while ((k << 1) < n) k <<= 1;
    return k;
}

node_hash mth_of(const node_hash* leaves, size_t n, const hash_ops& ops) {
    if (n == 0) return ops.empty();
    if (n == 1) return leaves[0];
    size_t k = pow2_floor(n);
    return node_hash_of(mth_of(leaves, k, ops), mth_of(leaves + k, n - k, ops), ops);
}

void path_impl(size_t m, const node_hash* leaves, size_t n,
               const hash_ops& ops, std::vector<node_hash>& out) {
    if (n == 1) return;
    size_t k = pow2_floor(n);
    if (m < k) {
        path_impl(m, leaves, k, ops, out);
        out.push_back(mth_of(leaves + k, n - k, ops));
    } else {
        path_impl(m - k, leaves + k, n - k, ops, out);
        out.push_back(mth_of(leaves, k, ops));
    }
}

void subproof_impl(size_t m, const node_hash* leaves, size_t n, bool b,
                   const hash_ops& ops, std::vector<node_hash>& out) {
    if (m == n) {
        if (!b) out.push_back(mth_of(leaves, n, ops));
        return;
    }
    size_t k = pow2_floor(n);
    if (m <= k) {
        subproof_impl(m, leaves, k, b, ops, out);
        out.push_back(mth_of(leaves + k, n - k, ops));
    } else {
        subproof_impl(m - k, leaves + k, n - k, false, ops, out);
        out.push_back(mth_of(leaves, k, ops));
    }
}

// ---- DER helpers ----

// Raw bytes of the TBSCertificate element (SEQUENCE header included).
std::optional<std::vector<uint8_t>> extract_tbs(const std::vector<uint8_t>& cert_der) {
    size_t off = 0;
    auto cert = x509::der::decode_tlv(cert_der.data(), cert_der.size(), off);
    if (!cert || cert->tag != x509::ASN1Tag::SEQUENCE) return std::nullopt;
    size_t io = 0;
    auto tbs = x509::der::decode_tlv(cert->value.data(), cert->value.size(), io);
    if (!tbs || tbs->tag != x509::ASN1Tag::SEQUENCE) return std::nullopt;
    return std::vector<uint8_t>(cert->value.begin(), cert->value.begin() + io);
}

// Top-level TBS elements, each kept as raw bytes.
std::vector<std::vector<uint8_t>> tbs_elements(const std::vector<uint8_t>& tbs_der) {
    std::vector<std::vector<uint8_t>> elems;
    size_t off = 0;
    auto tbs = x509::der::decode_tlv(tbs_der.data(), tbs_der.size(), off);
    if (!tbs || tbs->tag != x509::ASN1Tag::SEQUENCE) return elems;
    size_t pos = 0;
    while (pos < tbs->value.size()) {
        size_t start = pos;
        auto el = x509::der::decode_tlv(tbs->value.data(), tbs->value.size(), pos);
        if (!el) break;
        elems.emplace_back(tbs->value.begin() + start, tbs->value.begin() + pos);
    }
    return elems;
}

// Raw SPKI element bytes of a certificate (byte-exact for parsed certs).
std::optional<std::vector<uint8_t>> spki_raw(const x509::x509_cert& cert) {
    std::vector<uint8_t> tbs;
    if (!cert.tbs_raw.empty()) {
        tbs = cert.tbs_raw;
    } else {
        auto der = cert.to_der();
        auto t = extract_tbs(der);
        if (!t) return std::nullopt;
        tbs = std::move(*t);
    }
    auto elems = tbs_elements(tbs);
    size_t idx = 0;
    if (!elems.empty() && elems[0].size() >= 1 && (elems[0][0] & 0xE0) == 0xA0)
        idx = 1;  // skip [0] version
    // serial, sigAlg, issuer, validity, subject, spki
    if (idx + 5 >= elems.size()) return std::nullopt;
    return elems[idx + 5];
}

struct extn_info {
    bool critical = false;
    std::vector<uint8_t> extn_value;  // contents of extnValue OCTET STRING
};

std::optional<extn_info> find_extn(const std::vector<uint8_t>& cert_der,
                                   const uint8_t* oid, size_t oid_len) {
    auto tbs = extract_tbs(cert_der);
    if (!tbs) return std::nullopt;
    size_t off = 0;
    auto t = x509::der::decode_tlv(tbs->data(), tbs->size(), off);
    if (!t || t->tag != x509::ASN1Tag::SEQUENCE) return std::nullopt;
    size_t pos = 0;
    std::optional<x509::der::TLV> exts;
    while (pos < t->value.size()) {
        auto el = x509::der::decode_tlv(t->value.data(), t->value.size(), pos);
        if (!el) break;
        if (el->tag == x509::ASN1Tag::CONTEXT3) { exts = *el; break; }
    }
    if (!exts) return std::nullopt;
    size_t eo = 0;
    auto seq = x509::der::decode_tlv(exts->value.data(), exts->value.size(), eo);
    if (!seq || seq->tag != x509::ASN1Tag::SEQUENCE) return std::nullopt;
    size_t so = 0;
    while (so < seq->value.size()) {
        auto ext = x509::der::decode_tlv(seq->value.data(), seq->value.size(), so);
        if (!ext || ext->tag != x509::ASN1Tag::SEQUENCE) break;
        size_t xo = 0;
        auto eoid = x509::der::decode_tlv(ext->value.data(), ext->value.size(), xo);
        if (!eoid || eoid->tag != x509::ASN1Tag::OID) break;
        if (!oid_is(eoid->value, oid, oid_len)) continue;
        bool critical = false;
        auto next = x509::der::decode_tlv(ext->value.data(), ext->value.size(), xo);
        if (next && next->tag == x509::ASN1Tag::BOOLEAN) {
            critical = !next->value.empty() && next->value[0] != 0;
            next = x509::der::decode_tlv(ext->value.data(), ext->value.size(), xo);
        }
        if (!next || next->tag != x509::ASN1Tag::OCTET_STRING) break;
        return extn_info{critical, next->value};
    }
    return std::nullopt;
}

// Re-encode the TBS with extensions filtered/added. remove_oids entries are raw
// DER OID bytes; add_exts are appended in order after the kept ones.
std::optional<std::vector<uint8_t>> modify_tbs_extensions(
    const std::vector<uint8_t>& tbs_der,
    const std::vector<std::vector<uint8_t>>& remove_oids,
    const std::vector<x509::RawExtension>& add_exts) {
    size_t off = 0;
    auto tbs = x509::der::decode_tlv(tbs_der.data(), tbs_der.size(), off);
    if (!tbs || tbs->tag != x509::ASN1Tag::SEQUENCE) return std::nullopt;

    std::vector<uint8_t> body;   // TBS inner elements before extensions
    std::vector<uint8_t> kept;   // extensions SEQUENCE body after filtering
    size_t pos = 0;
    bool found = false;
    while (pos < tbs->value.size()) {
        size_t start = pos;
        auto el = x509::der::decode_tlv(tbs->value.data(), tbs->value.size(), pos);
        if (!el) return std::nullopt;
        if (el->tag == x509::ASN1Tag::CONTEXT3) {
            found = true;
            size_t eo = 0;
            auto seq = x509::der::decode_tlv(el->value.data(), el->value.size(), eo);
            if (!seq || seq->tag != x509::ASN1Tag::SEQUENCE) return std::nullopt;
            size_t so = 0;
            while (so < seq->value.size()) {
                size_t sstart = so;
                auto ext = x509::der::decode_tlv(seq->value.data(), seq->value.size(), so);
                if (!ext || ext->tag != x509::ASN1Tag::SEQUENCE) return std::nullopt;
                size_t xo = 0;
                auto eoid = x509::der::decode_tlv(ext->value.data(), ext->value.size(), xo);
                if (!eoid || eoid->tag != x509::ASN1Tag::OID) return std::nullopt;
                bool drop = false;
                for (const auto& r : remove_oids)
                    if (eoid->value == r) { drop = true; break; }
                if (!drop)
                    kept.insert(kept.end(), seq->value.begin() + sstart, seq->value.begin() + so);
            }
            break;
        }
        body.insert(body.end(), tbs->value.begin() + start, tbs->value.begin() + pos);
    }
    (void)found;

    for (const auto& raw : add_exts) {
        std::vector<uint8_t> ext;
        append(ext, x509::der::encode_oid(raw.oid));
        if (raw.critical) { ext.push_back(0x01); ext.push_back(0x01); ext.push_back(0xFF); }
        append(ext, x509::der::encode_octet_string(raw.extn_value.data(), raw.extn_value.size()));
        append(kept, x509::der::encode_sequence(ext));
    }
    if (!kept.empty())
        append(body, x509::der::encode_context(x509::ASN1Tag::CONTEXT3,
                                               x509::der::encode_sequence(kept)));
    return x509::der::encode_sequence(body);
}

// Sign a TBS with the given CA key (same convention as x509_builder).
bool sign_tbs(const std::vector<uint8_t>& tbs, x509::KeyType kt,
              const uint8_t* priv, size_t priv_len,
              uint8_t* out, size_t& out_len) {
    switch (kt) {
        case x509::KeyType::Ed25519:
            ed25519_sign(priv, tbs.data(), tbs.size(), out);
            out_len = 64;
            return true;
        case x509::KeyType::Ed448:
            ed448_sign(priv, tbs.data(), tbs.size(), out);
            out_len = 114;
            return true;
        case x509::KeyType::ECDSA_P256: {
            uint8_t hash[32];
            sha256_ctx ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, tbs.data(), tbs.size());
            sha256_final(&ctx, hash);
            ecdsa_p256_sign(priv, hash, 32, out);
            out_len = 64;
            return true;
        }
        case x509::KeyType::SM2: {
            uint8_t hash[32];
            sm3_ctx ctx;
            sm3_init(&ctx);
            sm3_update(&ctx, tbs.data(), tbs.size());
            sm3_final(&ctx, hash);
            sm2_sign(priv, hash, 32, out, nullptr);
            out_len = 64;
            return true;
        }
        case x509::KeyType::RSA_2048:
        case x509::KeyType::RSA_4096:
            // RSA signing needs the CA modulus which is not available from the
            // ca_priv argument alone; SM2/ECDSA/Ed25519/Ed448 are supported.
            return false;
    }
    return false;
}

} // namespace

// ============================================================================
// TLS-style encoding
// ============================================================================

std::vector<uint8_t> encode_u16(uint16_t v) {
    return {(uint8_t)(v >> 8), (uint8_t)v};
}

std::vector<uint8_t> encode_u64(uint64_t v) {
    std::vector<uint8_t> out(8);
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
    return out;
}

std::vector<uint8_t> encode_tls_vector16(const std::vector<uint8_t>& data) {
    if (data.size() > 0xFFFF) return {};
    auto out = encode_u16((uint16_t)data.size());
    append(out, data);
    return out;
}

std::vector<uint8_t> encode_tls_vector24(const std::vector<uint8_t>& data) {
    if (data.size() > 0xFFFFFF) return {};
    std::vector<uint8_t> out(3);
    out[0] = (uint8_t)(data.size() >> 16);
    out[1] = (uint8_t)(data.size() >> 8);
    out[2] = (uint8_t)data.size();
    append(out, data);
    return out;
}

bool read_u16(const uint8_t* data, size_t len, size_t& off, uint16_t& out) {
    if (off + 2 > len) return false;
    out = (uint16_t)((data[off] << 8) | data[off + 1]);
    off += 2;
    return true;
}

bool read_u64(const uint8_t* data, size_t len, size_t& off, uint64_t& out) {
    if (off + 8 > len) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out = (out << 8) | data[off + i];
    off += 8;
    return true;
}

bool read_vector16(const uint8_t* data, size_t len, size_t& off, std::vector<uint8_t>& out) {
    uint16_t vlen;
    if (!read_u16(data, len, off, vlen)) return false;
    if (off + vlen > len) return false;
    out.assign(data + off, data + off + vlen);
    off += vlen;
    return true;
}

bool read_vector24(const uint8_t* data, size_t len, size_t& off, std::vector<uint8_t>& out) {
    uint32_t vlen;
    if (!read_u24(data, len, off, vlen)) return false;
    if (off + vlen > len) return false;
    out.assign(data + off, data + off + vlen);
    off += vlen;
    return true;
}

// ============================================================================
// SM2 standard signatures (GB/T 32918, default ID "1234567812345678")
// ============================================================================

void sm2_sign_std(const uint8_t priv[SM2_KEY_SIZE],
                  const uint8_t pub[SM2_PUB_SIZE],
                  const uint8_t* msg, size_t msg_len,
                  uint8_t sig[SM2_SIG_SIZE]) {
    uint8_t za[SM2_ZA_SIZE];
    sm2_compute_za((const uint8_t*)SM2_DEFAULT_ID, sizeof(SM2_DEFAULT_ID) - 1,
                   pub, pub + 32, za);
    sm2_sign(priv, msg, msg_len, sig, za);
}

bool sm2_verify_std(const uint8_t pub[SM2_PUB_SIZE],
                    const uint8_t* msg, size_t msg_len,
                    const uint8_t sig[SM2_SIG_SIZE]) {
    uint8_t za[SM2_ZA_SIZE];
    sm2_compute_za((const uint8_t*)SM2_DEFAULT_ID, sizeof(SM2_DEFAULT_ID) - 1,
                   pub, pub + 32, za);
    return sm2_verify(pub, msg, msg_len, sig, za);
}

// ============================================================================
// SM3 Merkle tree
// ============================================================================

void sm3_leaf_hash(const uint8_t* leaf, size_t leaf_len, uint8_t out[SM3_DIGEST_SIZE]) {
    sm3_ctx ctx;
    sm3_init(&ctx);
    const uint8_t prefix = 0x00;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, leaf, leaf_len);
    sm3_final(&ctx, out);
}

void sm3_node_hash(const uint8_t l[SM3_DIGEST_SIZE],
                   const uint8_t r[SM3_DIGEST_SIZE],
                   uint8_t out[SM3_DIGEST_SIZE]) {
    sm3_ctx ctx;
    sm3_init(&ctx);
    const uint8_t prefix = 0x01;
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, l, SM3_DIGEST_SIZE);
    sm3_update(&ctx, r, SM3_DIGEST_SIZE);
    sm3_final(&ctx, out);
}

void sha256_leaf_hash(const uint8_t* leaf, size_t leaf_len, uint8_t out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    const uint8_t prefix = 0x00;
    sha256_update(&ctx, &prefix, 1);
    if (leaf_len > 0) sha256_update(&ctx, leaf, leaf_len);
    sha256_final(&ctx, out);
}

void sha256_node_hash(const uint8_t l[32], const uint8_t r[32], uint8_t out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    const uint8_t prefix = 0x01;
    sha256_update(&ctx, &prefix, 1);
    sha256_update(&ctx, l, 32);
    sha256_update(&ctx, r, 32);
    sha256_final(&ctx, out);
}

node_hash merkle_root(const std::vector<node_hash>& leaf_hashes, CtHashAlg alg) {
    if (leaf_hashes.empty()) return ops_for(alg).empty();
    return mth_of(leaf_hashes.data(), leaf_hashes.size(), ops_for(alg));
}

std::vector<node_hash> audit_path(size_t leaf_index,
                                  const std::vector<node_hash>& leaf_hashes,
                                  CtHashAlg alg) {
    if (leaf_index >= leaf_hashes.size()) return {};
    std::vector<node_hash> out;
    path_impl(leaf_index, leaf_hashes.data(), leaf_hashes.size(), ops_for(alg), out);
    return out;
}

bool verify_audit_path(size_t leaf_index, size_t tree_size,
                       const node_hash& leaf_hash,
                       const std::vector<node_hash>& path,
                       const node_hash& root, CtHashAlg alg) {
    if (leaf_index >= tree_size) return false;
    size_t fn = leaf_index;
    size_t sn = tree_size - 1;
    node_hash fr = leaf_hash;
    const auto& ops = ops_for(alg);
    for (const auto& c : path) {
        if (sn == 0) return false;
        if ((fn & 1) || fn == sn) {
            fr = node_hash_of(c, fr, ops);
            if ((fn & 1) == 0) {
                while (fn != 0 && (fn & 1) == 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            fr = node_hash_of(fr, c, ops);
        }
        fn >>= 1;
        sn >>= 1;
    }
    return fr == root && sn == 0;
}

std::vector<node_hash> consistency_proof(size_t first, size_t second,
                                         const std::vector<node_hash>& leaf_hashes,
                                         CtHashAlg alg) {
    if (first == 0 || first > second || second > leaf_hashes.size()) return {};
    std::vector<node_hash> out;
    subproof_impl(first, leaf_hashes.data(), second, true, ops_for(alg), out);
    return out;
}

bool verify_consistency(size_t first, size_t second,
                        const node_hash& first_root,
                        const node_hash& second_root,
                        const std::vector<node_hash>& proof, CtHashAlg alg) {
    if (first > second || first == 0) return false;
    if (first == second) return proof.empty() && first_root == second_root;

    std::vector<node_hash> p = proof;
    if ((first & (first - 1)) == 0) p.insert(p.begin(), first_root);
    if (p.empty()) return false;

    size_t fn = first - 1;
    size_t sn = second - 1;
    while (fn & 1) {
        fn >>= 1;
        sn >>= 1;
    }
    node_hash fr = p[0];
    node_hash sr = p[0];
    const auto& ops = ops_for(alg);
    for (size_t i = 1; i < p.size(); ++i) {
        const auto& c = p[i];
        if (sn == 0) return false;
        if ((fn & 1) || fn == sn) {
            fr = node_hash_of(c, fr, ops);
            sr = node_hash_of(c, sr, ops);
            while (fn != 0 && (fn & 1) == 0) {
                fn >>= 1;
                sn >>= 1;
            }
        } else {
            sr = node_hash_of(sr, c, ops);
        }
        fn >>= 1;
        sn >>= 1;
    }
    return fr == first_root && sr == second_root && sn == 0;
}

// ============================================================================
// PreCert / MerkleTreeLeaf
// ============================================================================

std::vector<uint8_t> serialize_precert(const pre_cert& pc) {
    std::vector<uint8_t> out;
    out.insert(out.end(), pc.issuer_key_hash.begin(), pc.issuer_key_hash.end());
    append(out, encode_tls_vector24(pc.tbs_certificate));
    return out;
}

std::optional<pre_cert> deserialize_precert(const uint8_t* data, size_t len) {
    pre_cert pc;
    size_t off = 0;
    if (off + CT_LOG_ID_SIZE > len) return std::nullopt;
    memcpy(pc.issuer_key_hash.data(), data + off, CT_LOG_ID_SIZE);
    off += CT_LOG_ID_SIZE;
    if (!read_vector24(data, len, off, pc.tbs_certificate)) return std::nullopt;
    if (off != len) return std::nullopt;
    return pc;
}

std::vector<uint8_t> serialize_merkle_tree_leaf(const merkle_tree_leaf& leaf) {
    std::vector<uint8_t> out;
    out.push_back(leaf.version);
    out.push_back((uint8_t)leaf.leaf_type);
    append(out, encode_u64(leaf.timestamp));
    out.push_back((uint8_t)((uint16_t)leaf.entry_type >> 8));
    out.push_back((uint8_t)((uint16_t)leaf.entry_type & 0xFF));
    append(out, leaf.signed_entry);
    append(out, encode_tls_vector16(leaf.extensions));
    return out;
}

std::optional<merkle_tree_leaf> deserialize_merkle_tree_leaf(const uint8_t* data, size_t len) {
    merkle_tree_leaf leaf;
    size_t off = 0;
    if (off + 2 > len) return std::nullopt;
    leaf.version = data[off++];
    leaf.leaf_type = (MerkleLeafType)data[off++];
    if (!read_u64(data, len, off, leaf.timestamp)) return std::nullopt;
    uint16_t et;
    if (!read_u16(data, len, off, et)) return std::nullopt;
    leaf.entry_type = (LogEntryType)et;

    size_t signed_end = 0;
    if (leaf.entry_type == LogEntryType::X509_ENTRY) {
        // signed_entry is one DER-encoded certificate (self-delimiting).
        size_t total = 0;
        if (!tlv_total_len(data, len, off, total)) return std::nullopt;
        signed_end = off + total;
        if (signed_end > len) return std::nullopt;
    } else if (leaf.entry_type == LogEntryType::PRECERT_ENTRY) {
        // PreCert: issuer_key_hash[32] + tbs<0..2^24-1>
        if (off + CT_LOG_ID_SIZE + 3 > len) return std::nullopt;
        size_t pos = off + CT_LOG_ID_SIZE;
        uint32_t tbs_len;
        if (!read_u24(data, len, pos, tbs_len)) return std::nullopt;
        signed_end = pos + tbs_len;
        if (signed_end > len) return std::nullopt;
    } else {
        return std::nullopt;
    }
    leaf.signed_entry.assign(data + off, data + signed_end);
    off = signed_end;

    // Remaining bytes must be the extensions vector (u16 length + payload).
    if (len - off < 2) return std::nullopt;
    uint16_t ext_len;
    size_t eo = off;
    if (!read_u16(data, len, eo, ext_len)) return std::nullopt;
    if (eo + ext_len != len) return std::nullopt;
    leaf.extensions.assign(data + eo, data + len);
    return leaf;
}

std::vector<uint8_t> make_precert_signed_entry(const pre_cert& pc) {
    return serialize_precert(pc);
}

// ============================================================================
// SCT
// ============================================================================

std::vector<uint8_t> sct_signed_data(uint64_t timestamp,
                                     LogEntryType entry_type,
                                     const std::vector<uint8_t>& signed_entry,
                                     const std::vector<uint8_t>& extensions) {
    std::vector<uint8_t> out;
    out.push_back(CT_VERSION_V1);
    out.push_back((uint8_t)SignatureType::CERTIFICATE_TIMESTAMP);
    append(out, encode_u64(timestamp));
    out.push_back((uint8_t)((uint16_t)entry_type >> 8));
    out.push_back((uint8_t)((uint16_t)entry_type & 0xFF));
    append(out, signed_entry);
    append(out, encode_tls_vector16(extensions));
    return out;
}

std::vector<uint8_t> serialize_sct(const signed_certificate_timestamp& sct) {
    std::vector<uint8_t> out;
    out.push_back(sct.version);
    out.insert(out.end(), sct.log_id.begin(), sct.log_id.end());
    append(out, encode_u64(sct.timestamp));
    append(out, encode_tls_vector16(sct.extensions));
    out.push_back(sct.hash_algorithm);
    out.push_back(sct.signature_algorithm);
    append(out, encode_tls_vector16(sct.signature));
    return out;
}

std::optional<signed_certificate_timestamp> deserialize_sct(const uint8_t* data, size_t len) {
    signed_certificate_timestamp sct;
    size_t off = 0;
    if (off + 1 + CT_LOG_ID_SIZE > len) return std::nullopt;
    sct.version = data[off++];
    memcpy(sct.log_id.data(), data + off, CT_LOG_ID_SIZE);
    off += CT_LOG_ID_SIZE;
    if (!read_u64(data, len, off, sct.timestamp)) return std::nullopt;
    if (!read_vector16(data, len, off, sct.extensions)) return std::nullopt;
    if (off + 2 > len) return std::nullopt;
    sct.hash_algorithm = data[off++];
    sct.signature_algorithm = data[off++];
    if (!read_vector16(data, len, off, sct.signature)) return std::nullopt;
    if (off != len) return std::nullopt;
    return sct;
}

signed_certificate_timestamp issue_sct(const uint8_t log_priv[SM2_KEY_SIZE],
                                       const uint8_t log_pub[SM2_PUB_SIZE],
                                       const uint8_t log_id[CT_LOG_ID_SIZE],
                                       uint64_t timestamp,
                                       LogEntryType entry_type,
                                       const std::vector<uint8_t>& signed_entry,
                                       const std::vector<uint8_t>& extensions) {
    signed_certificate_timestamp sct;
    sct.version = CT_VERSION_V1;
    memcpy(sct.log_id.data(), log_id, CT_LOG_ID_SIZE);
    sct.timestamp = timestamp;
    sct.extensions = extensions;
    auto data = sct_signed_data(timestamp, entry_type, signed_entry, extensions);
    uint8_t sig[SM2_SIG_SIZE];
    sm2_sign_std(log_priv, log_pub, data.data(), data.size(), sig);
    sct.signature.assign(sig, sig + SM2_SIG_SIZE);
    return sct;
}

bool verify_sct(const signed_certificate_timestamp& sct,
                const uint8_t log_pub[SM2_PUB_SIZE],
                LogEntryType entry_type,
                const std::vector<uint8_t>& signed_entry) {
    if (sct.version != CT_VERSION_V1) return false;
    if (sct.hash_algorithm != CT_HASH_ALG_SM3 ||
        sct.signature_algorithm != CT_SIG_ALG_SM2)
        return false;
    if (sct.signature.size() != SM2_SIG_SIZE) return false;
    auto data = sct_signed_data(sct.timestamp, entry_type, signed_entry, sct.extensions);
    return sm2_verify_std(log_pub, data.data(), data.size(), sct.signature.data());
}

signed_certificate_timestamp issue_sct_std(const uint8_t log_priv[32],
                                           const uint8_t log_pub[64],
                                           const uint8_t log_id[CT_LOG_ID_SIZE],
                                           uint64_t timestamp,
                                           LogEntryType entry_type,
                                           const std::vector<uint8_t>& signed_entry,
                                           const std::vector<uint8_t>& extensions) {
    (void)log_pub; // ECDSA 签名仅需私钥
    signed_certificate_timestamp sct;
    sct.version = CT_VERSION_V1;
    memcpy(sct.log_id.data(), log_id, CT_LOG_ID_SIZE);
    sct.timestamp = timestamp;
    sct.extensions = extensions;
    sct.hash_algorithm = CT_HASH_ALG_SHA256;
    sct.signature_algorithm = CT_SIG_ALG_ECDSA;
    auto data = sct_signed_data(timestamp, entry_type, signed_entry, extensions);
    uint8_t sig[ECDSA_P256_SIG_SIZE];
    ecdsa_p256_sign(log_priv, data.data(), data.size(), sig);
    sct.signature.assign(sig, sig + ECDSA_P256_SIG_SIZE);
    return sct;
}

bool verify_sct_std(const signed_certificate_timestamp& sct,
                    const uint8_t log_pub[64],
                    LogEntryType entry_type,
                    const std::vector<uint8_t>& signed_entry) {
    if (sct.version != CT_VERSION_V1) return false;
    if (sct.hash_algorithm != CT_HASH_ALG_SHA256 ||
        sct.signature_algorithm != CT_SIG_ALG_ECDSA)
        return false;
    if (sct.signature.size() != ECDSA_P256_SIG_SIZE) return false;
    auto data = sct_signed_data(sct.timestamp, entry_type, signed_entry, sct.extensions);
    return ecdsa_p256_verify(log_pub, data.data(), data.size(), sct.signature.data());
}

signed_certificate_timestamp issue_sct_rsa(const rsa_crt_key& log_priv,
                                           const uint8_t log_id[CT_LOG_ID_SIZE],
                                           uint64_t timestamp,
                                           LogEntryType entry_type,
                                           const std::vector<uint8_t>& signed_entry,
                                           const std::vector<uint8_t>& extensions) {
    signed_certificate_timestamp sct;
    sct.version = CT_VERSION_V1;
    memcpy(sct.log_id.data(), log_id, CT_LOG_ID_SIZE);
    sct.timestamp = timestamp;
    sct.extensions = extensions;
    sct.hash_algorithm = CT_HASH_ALG_SHA256;
    sct.signature_algorithm = CT_SIG_ALG_RSA;
    auto data = sct_signed_data(timestamp, entry_type, signed_entry, extensions);
    uint8_t sig[256];
    if (!rsassa_pkcs1v15_sign(log_priv, data.data(), data.size(),
                              k_sha256_digest_info, sizeof(k_sha256_digest_info), sig))
        return {}; // RSA-2048 + SHA-256 下不会发生
    sct.signature.assign(sig, sig + sizeof(sig));
    return sct;
}

bool verify_sct_rsa(const signed_certificate_timestamp& sct,
                    const rsa_public_key& log_pub,
                    LogEntryType entry_type,
                    const std::vector<uint8_t>& signed_entry) {
    if (sct.version != CT_VERSION_V1) return false;
    if (sct.hash_algorithm != CT_HASH_ALG_SHA256 ||
        sct.signature_algorithm != CT_SIG_ALG_RSA)
        return false;
    if (sct.signature.size() != 256) return false;
    auto data = sct_signed_data(sct.timestamp, entry_type, signed_entry, sct.extensions);
    return rsassa_pkcs1v15_verify(log_pub, data.data(), data.size(),
                                  k_sha256_digest_info, sizeof(k_sha256_digest_info),
                                  sct.signature.data());
}

// ============================================================================
// STH
// ============================================================================

std::vector<uint8_t> sth_signed_data(const signed_tree_head& sth) {
    std::vector<uint8_t> out;
    out.push_back(sth.version);
    out.push_back((uint8_t)SignatureType::TREE_HASH);
    append(out, encode_u64(sth.timestamp));
    append(out, encode_u64(sth.tree_size));
    out.insert(out.end(), sth.root_hash.begin(), sth.root_hash.end());
    return out;
}

std::vector<uint8_t> serialize_sth(const signed_tree_head& sth) {
    std::vector<uint8_t> out;
    out.push_back(sth.version);
    append(out, encode_u64(sth.timestamp));
    append(out, encode_u64(sth.tree_size));
    out.insert(out.end(), sth.root_hash.begin(), sth.root_hash.end());
    out.push_back(sth.hash_algorithm);
    out.push_back(sth.signature_algorithm);
    append(out, encode_tls_vector16(sth.signature));
    return out;
}

signed_tree_head sign_sth(const uint8_t log_priv[SM2_KEY_SIZE],
                          const uint8_t log_pub[SM2_PUB_SIZE],
                          uint64_t timestamp, uint64_t tree_size,
                          const node_hash& root_hash) {
    signed_tree_head sth;
    sth.version = CT_VERSION_V1;
    sth.timestamp = timestamp;
    sth.tree_size = tree_size;
    sth.root_hash = root_hash;
    auto data = sth_signed_data(sth);
    uint8_t sig[SM2_SIG_SIZE];
    sm2_sign_std(log_priv, log_pub, data.data(), data.size(), sig);
    sth.signature.assign(sig, sig + SM2_SIG_SIZE);
    return sth;
}

bool verify_sth(const signed_tree_head& sth, const uint8_t log_pub[SM2_PUB_SIZE]) {
    if (sth.version != CT_VERSION_V1) return false;
    if (sth.hash_algorithm != CT_HASH_ALG_SM3 ||
        sth.signature_algorithm != CT_SIG_ALG_SM2)
        return false;
    if (sth.signature.size() != SM2_SIG_SIZE) return false;
    auto data = sth_signed_data(sth);
    return sm2_verify_std(log_pub, data.data(), data.size(), sth.signature.data());
}

signed_tree_head sign_sth_std(const uint8_t log_priv[32],
                              const uint8_t log_pub[64],
                              uint64_t timestamp, uint64_t tree_size,
                              const node_hash& root_hash) {
    (void)log_pub; // ECDSA 签名仅需私钥
    signed_tree_head sth;
    sth.version = CT_VERSION_V1;
    sth.timestamp = timestamp;
    sth.tree_size = tree_size;
    sth.root_hash = root_hash;
    sth.hash_algorithm = CT_HASH_ALG_SHA256;
    sth.signature_algorithm = CT_SIG_ALG_ECDSA;
    auto data = sth_signed_data(sth);
    uint8_t sig[ECDSA_P256_SIG_SIZE];
    ecdsa_p256_sign(log_priv, data.data(), data.size(), sig);
    sth.signature.assign(sig, sig + ECDSA_P256_SIG_SIZE);
    return sth;
}

bool verify_sth_std(const signed_tree_head& sth, const uint8_t log_pub[64]) {
    if (sth.version != CT_VERSION_V1) return false;
    if (sth.hash_algorithm != CT_HASH_ALG_SHA256 ||
        sth.signature_algorithm != CT_SIG_ALG_ECDSA)
        return false;
    if (sth.signature.size() != ECDSA_P256_SIG_SIZE) return false;
    auto data = sth_signed_data(sth);
    return ecdsa_p256_verify(log_pub, data.data(), data.size(), sth.signature.data());
}

signed_tree_head sign_sth_rsa(const rsa_crt_key& log_priv,
                              uint64_t timestamp, uint64_t tree_size,
                              const node_hash& root_hash) {
    signed_tree_head sth;
    sth.version = CT_VERSION_V1;
    sth.timestamp = timestamp;
    sth.tree_size = tree_size;
    sth.root_hash = root_hash;
    sth.hash_algorithm = CT_HASH_ALG_SHA256;
    sth.signature_algorithm = CT_SIG_ALG_RSA;
    auto data = sth_signed_data(sth);
    uint8_t sig[256];
    if (!rsassa_pkcs1v15_sign(log_priv, data.data(), data.size(),
                              k_sha256_digest_info, sizeof(k_sha256_digest_info), sig))
        return {};
    sth.signature.assign(sig, sig + sizeof(sig));
    return sth;
}

bool verify_sth_rsa(const signed_tree_head& sth, const rsa_public_key& log_pub) {
    if (sth.version != CT_VERSION_V1) return false;
    if (sth.hash_algorithm != CT_HASH_ALG_SHA256 ||
        sth.signature_algorithm != CT_SIG_ALG_RSA)
        return false;
    if (sth.signature.size() != 256) return false;
    auto data = sth_signed_data(sth);
    return rsassa_pkcs1v15_verify(log_pub, data.data(), data.size(),
                                  k_sha256_digest_info, sizeof(k_sha256_digest_info),
                                  sth.signature.data());
}

// ============================================================================
// X.509 integration
// ============================================================================

node_hash compute_log_id(const x509::x509_cert& log_cert) {
    auto spki = spki_raw(log_cert);
    node_hash out{};
    if (spki) sm3_hash(out.data(), spki->data(), spki->size());
    return out;
}

node_hash compute_log_id_std(const x509::x509_cert& log_cert) {
    auto spki = spki_raw(log_cert);
    node_hash out{};
    if (spki) sha256(spki->data(), spki->size(), out.data());
    return out;
}

std::vector<uint8_t> serialize_cert_chain(const std::vector<std::vector<uint8_t>>& chain) {
    std::vector<uint8_t> out;
    for (const auto& c : chain) {
        if (c.size() > 0xFFFFFF) return {};
        append(out, encode_tls_vector24(c));
    }
    return out;
}

x509::x509_cert finalize_precert(const x509::x509_cert& precert,
                                 const std::vector<signed_certificate_timestamp>& scts,
                                 x509::KeyType sign_key_type,
                                 const uint8_t* ca_priv, size_t ca_priv_len) {
    x509::x509_cert out = precert;
    auto tbs = extract_tbs(precert.to_der());
    if (!tbs) return out;

    std::vector<std::vector<uint8_t>> remove_oids = {
        {std::begin(OID_CT_POISON), std::end(OID_CT_POISON)},
        {std::begin(OID_SCT_LIST), std::end(OID_SCT_LIST)},
    };
    x509::RawExtension sct_ext;
    sct_ext.oid.assign(std::begin(OID_SCT_LIST), std::end(OID_SCT_LIST));
    sct_ext.critical = false;
    sct_ext.extn_value = encode_sct_list_extn(scts);

    auto new_tbs = modify_tbs_extensions(*tbs, remove_oids, {sct_ext});
    if (!new_tbs) return out;

    uint8_t sig_buf[256];
    size_t sig_len = 0;
    if (!sign_tbs(*new_tbs, sign_key_type, ca_priv, ca_priv_len, sig_buf, sig_len))
        return out;

    std::vector<uint8_t> body;
    append(body, *new_tbs);
    append(body, x509::der::encode_sig_algo(sign_key_type));
    append(body, x509::der::encode_bit_string(sig_buf, sig_len, 0));
    auto final_der = x509::der::encode_sequence(body);

    auto parsed = x509::x509_cert::from_der(final_der);
    if (parsed) out = std::move(*parsed);
    return out;
}

std::optional<std::vector<uint8_t>> precert_tbs_from_final(const std::vector<uint8_t>& final_cert_der) {
    auto tbs = extract_tbs(final_cert_der);
    if (!tbs) return std::nullopt;
    std::vector<std::vector<uint8_t>> remove_oids = {
        {std::begin(OID_SCT_LIST), std::end(OID_SCT_LIST)},
    };
    return modify_tbs_extensions(*tbs, remove_oids, {});
}

std::vector<uint8_t> encode_sct_list_extn(const std::vector<signed_certificate_timestamp>& scts) {
    std::vector<uint8_t> tls_list;
    for (const auto& s : scts) append(tls_list, serialize_sct(s));
    auto wrapped = encode_tls_vector16(tls_list);
    return x509::der::encode_octet_string(wrapped.data(), wrapped.size());
}

std::optional<std::vector<signed_certificate_timestamp>>
decode_sct_list_extn(const std::vector<uint8_t>& extn_value) {
    size_t off = 0;
    auto oct = x509::der::decode_tlv(extn_value.data(), extn_value.size(), off);
    if (!oct || oct->tag != x509::ASN1Tag::OCTET_STRING) return std::nullopt;
    size_t lo = 0;
    uint16_t total;
    if (!read_u16(oct->value.data(), oct->value.size(), lo, total)) return std::nullopt;
    if ((size_t)total != oct->value.size() - 2) return std::nullopt;
    std::vector<signed_certificate_timestamp> scts;
    while (lo < oct->value.size()) {
        auto sct = deserialize_sct(oct->value.data() + lo, oct->value.size() - lo);
        if (!sct) return std::nullopt;
        lo += serialize_sct(*sct).size();
        scts.push_back(std::move(*sct));
    }
    return scts;
}

std::optional<std::vector<signed_certificate_timestamp>>
scts_from_cert(const std::vector<uint8_t>& cert_der) {
    auto ext = find_extn(cert_der, OID_SCT_LIST, sizeof(OID_SCT_LIST));
    if (!ext) return std::nullopt;
    return decode_sct_list_extn(ext->extn_value);
}

// ============================================================================
// In-memory CT log (SM3+SM2 国密 / SHA-256+ECDSA 国际)
// ============================================================================

ct_log::ct_log(const uint8_t log_priv[32], const uint8_t log_pub[64], clock_fn now_fn)
    : ct_log(CtHashAlg::SM3, CtSigAlg::SM2, log_priv, log_pub, now_fn) {}

ct_log::ct_log(CtHashAlg hash_alg, CtSigAlg sig_alg,
               const uint8_t log_priv[32], const uint8_t log_pub[64],
               clock_fn now_fn)
    : hash_alg_(hash_alg), sig_alg_(sig_alg), now_fn_(now_fn) {
    memcpy(log_priv_, log_priv, 32);
    memcpy(log_pub_, log_pub, 64);
    x509::KeyType kt = (hash_alg == CtHashAlg::SHA256 && sig_alg == CtSigAlg::ECDSA_P256)
                           ? x509::KeyType::ECDSA_P256
                           : x509::KeyType::SM2;
    auto spki = x509::der::encode_spki(kt, log_pub, 64);
    if (hash_alg == CtHashAlg::SHA256)
        sha256(spki.data(), spki.size(), log_id_.data());
    else
        sm3_hash(log_id_.data(), spki.data(), spki.size());
}

ct_log::ct_log(const rsa_crt_key& log_priv, const rsa_public_key& log_pub,
               clock_fn now_fn)
    : hash_alg_(CtHashAlg::SHA256), sig_alg_(CtSigAlg::RSA),
      rsa_priv_(log_priv), rsa_pub_(log_pub), now_fn_(now_fn) {
    // LogID = SHA-256(SubjectPublicKeyInfo DER)；RSA-2048 公钥 = n || 0x010001
    uint8_t p[259];
    log_pub.n.to_bytes(p);
    p[256] = 1;
    p[257] = 0;
    p[258] = 1;
    auto spki = x509::der::encode_spki(x509::KeyType::RSA_2048, p, sizeof(p));
    sha256(spki.data(), spki.size(), log_id_.data());
}

void ct_log::accept_root(const std::vector<uint8_t>& root_der) {
    roots_.push_back(root_der);
}

void ct_log::clear_roots() {
    roots_.clear();
}

bool ct_log::chain_ok(const std::vector<std::vector<uint8_t>>& chain,
                      bool expect_precert, std::string* error) const {
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        return false;
    };
    if (chain.empty()) return fail("empty chain");

    bool root_ok = false;
    for (const auto& r : roots_)
        if (r == chain.back()) { root_ok = true; break; }
    if (!root_ok) return fail("root certificate not accepted");

    std::vector<x509::x509_cert> certs;
    certs.reserve(chain.size());
    for (const auto& der : chain) {
        auto c = x509::x509_cert::from_der(der);
        if (!c) return fail("bad certificate DER");
        certs.push_back(std::move(*c));
    }

    if (expect_precert) {
        if (!find_extn(chain[0], OID_CT_POISON, sizeof(OID_CT_POISON)))
            return fail("first certificate is not a precert (ct_poison missing)");
        if (certs.size() < 2) return fail("precert chain missing issuer");
        if (!certs[0].verify_signature(certs[1])) return fail("precert signature invalid");
        for (size_t i = 1; i + 1 < certs.size(); ++i)
            if (!certs[i].verify_signature(certs[i + 1]))
                return fail("chain signature invalid");
    } else {
        if (find_extn(chain[0], OID_CT_POISON, sizeof(OID_CT_POISON)))
            return fail("poisoned certificate submitted as final chain");
        for (size_t i = 0; i + 1 < certs.size(); ++i)
            if (!certs[i].verify_signature(certs[i + 1]))
                return fail("chain signature invalid");
    }

    uint64_t t = now();
    for (const auto& c : certs)
        if (!c.is_valid_at(t)) return fail("certificate expired or not yet valid");
    return true;
}

std::optional<signed_certificate_timestamp>
ct_log::add_chain(const std::vector<std::vector<uint8_t>>& chain, std::string* error) {
    if (!chain_ok(chain, false, error)) return std::nullopt;
    merkle_tree_leaf leaf;
    leaf.entry_type = LogEntryType::X509_ENTRY;
    leaf.signed_entry = chain[0];
    return append_entry(leaf, {}, error);
}

std::optional<signed_certificate_timestamp>
ct_log::add_pre_chain(const std::vector<std::vector<uint8_t>>& chain, std::string* error) {
    if (!chain_ok(chain, true, error)) return std::nullopt;

    auto issuer = x509::x509_cert::from_der(chain[1]);
    if (!issuer) {
        if (error) *error = "bad issuer certificate";
        return std::nullopt;
    }
    auto spki = spki_raw(*issuer);
    if (!spki) {
        if (error) *error = "issuer SPKI unavailable";
        return std::nullopt;
    }

    pre_cert pc;
    if (hash_alg_ == CtHashAlg::SHA256)
        sha256(spki->data(), spki->size(), pc.issuer_key_hash.data());
    else
        sm3_hash(pc.issuer_key_hash.data(), spki->data(), spki->size());
    auto tbs = extract_tbs(chain[0]);
    if (!tbs) {
        if (error) *error = "bad precert TBS";
        return std::nullopt;
    }
    pc.tbs_certificate = std::move(*tbs);

    merkle_tree_leaf leaf;
    leaf.entry_type = LogEntryType::PRECERT_ENTRY;
    leaf.signed_entry = make_precert_signed_entry(pc);

    // extra_data = PrecertChainEntry { pre_certificate, precertificate_chain }
    std::vector<uint8_t> extra;
    append(extra, encode_tls_vector16(chain[0]));
    std::vector<uint8_t> rest;
    for (size_t i = 1; i < chain.size(); ++i) append(rest, encode_tls_vector24(chain[i]));
    append(extra, encode_tls_vector16(rest));

    return append_entry(leaf, std::move(extra), error);
}

signed_tree_head ct_log::get_sth() {
    signed_tree_head sth;
    sth.tree_size = leaf_hashes_.size();
    sth.root_hash = merkle_root(leaf_hashes_, hash_alg_);
    uint64_t ts = now();
    if (ts <= last_entry_time_) ts = last_entry_time_;
    if (ts <= last_sth_time_) ts = last_sth_time_ + 1;
    sth.timestamp = ts;
    last_sth_time_ = ts;
    if (sig_alg_ == CtSigAlg::ECDSA_P256)
        return sign_sth_std(log_priv_, log_pub_, sth.timestamp, sth.tree_size, sth.root_hash);
    if (sig_alg_ == CtSigAlg::RSA)
        return sign_sth_rsa(*rsa_priv_, sth.timestamp, sth.tree_size, sth.root_hash);
    return sign_sth(log_priv_, log_pub_, sth.timestamp, sth.tree_size, sth.root_hash);
}

std::vector<node_hash> ct_log::get_sth_consistency(uint64_t first, uint64_t second) const {
    if (first > second || second > leaf_hashes_.size()) return {};
    return consistency_proof((size_t)first, (size_t)second, leaf_hashes_, hash_alg_);
}

bool ct_log::get_proof_by_hash(const node_hash& leaf_hash, uint64_t tree_size,
                               uint64_t* leaf_index,
                               std::vector<node_hash>* path) const {
    if (tree_size > leaf_hashes_.size()) return false;
    for (size_t i = 0; i < (size_t)tree_size; ++i) {
        if (leaf_hashes_[i] == leaf_hash) {
            if (leaf_index) *leaf_index = i;
            if (path) {
                *path = audit_path(i, std::vector<node_hash>(
                    leaf_hashes_.begin(), leaf_hashes_.begin() + tree_size), hash_alg_);
            }
            return true;
        }
    }
    return false;
}

bool ct_log::get_entries(uint64_t start, uint64_t end,
                         std::vector<std::vector<uint8_t>>* leaf_inputs,
                         std::vector<std::vector<uint8_t>>* extra_datas) const {
    if (start > end || end >= entries_.size()) return false;
    if (leaf_inputs) leaf_inputs->clear();
    if (extra_datas) extra_datas->clear();
    for (uint64_t i = start; i <= end; ++i) {
        if (leaf_inputs) leaf_inputs->push_back(serialize_merkle_tree_leaf(entries_[i]));
        if (extra_datas) extra_datas->push_back(extra_datas_[i]);
    }
    return true;
}

std::optional<signed_certificate_timestamp>
ct_log::append_entry(merkle_tree_leaf leaf, std::vector<uint8_t> extra_data,
                     std::string* error) {
    uint64_t ts = now();
    if (ts <= last_entry_time_) ts = last_entry_time_ + 1;
    leaf.timestamp = ts;
    last_entry_time_ = ts;

    auto serialized = serialize_merkle_tree_leaf(leaf);
    node_hash lh;
    if (hash_alg_ == CtHashAlg::SHA256)
        sha256_leaf_hash(serialized.data(), serialized.size(), lh.data());
    else
        sm3_leaf_hash(serialized.data(), serialized.size(), lh.data());

    std::optional<signed_certificate_timestamp> sct;
    if (sig_alg_ == CtSigAlg::ECDSA_P256)
        sct = issue_sct_std(log_priv_, log_pub_, log_id_.data(), ts,
                            leaf.entry_type, leaf.signed_entry, leaf.extensions);
    else if (sig_alg_ == CtSigAlg::RSA)
        sct = issue_sct_rsa(*rsa_priv_, log_id_.data(), ts,
                            leaf.entry_type, leaf.signed_entry, leaf.extensions);
    else
        sct = issue_sct(log_priv_, log_pub_, log_id_.data(), ts,
                        leaf.entry_type, leaf.signed_entry, leaf.extensions);
    entries_.push_back(std::move(leaf));
    extra_datas_.push_back(std::move(extra_data));
    leaf_hashes_.push_back(lh);
    (void)error;
    return sct;
}

} // namespace jpssl::ct
