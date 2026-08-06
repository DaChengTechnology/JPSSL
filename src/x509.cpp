/**
 * x509.cpp — X.509 v3 DER 编解码、证书生成与验证 (RFC 5280, 8410, 5758, GB/T 35275)
 * 完全自包含，不依赖 OpenSSL。
 */
#include "x509.hpp"
#include "base64.hpp"
#include "hmac.hpp"
#include "aes.hpp"
#include "ed25519.hpp"
#include "ed448.hpp"
#include "ecdsa.hpp"
#include "sm2.hpp"
#include "rsa.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <algorithm>

namespace jpssl::x509 {

namespace {
// 辅助：安全地追加 vector（避免临时对象导致的 iterator UB）
inline void append(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}
} // anonymous

// ═══════════════════════════════════════════════════════════════════════
namespace der {

// ── 长度编码 ──────────────────────────────────────────────────────────────
void encode_length(std::vector<uint8_t>& out, size_t len) {
    if (len < 0x80) { out.push_back((uint8_t)len); return; }
    uint8_t buf[8]; int n = 0;
    for (size_t v = len; v > 0; v >>= 8) buf[n++] = (uint8_t)(v & 0xFF);
    out.push_back((uint8_t)(0x80 | n));
    while (n--) out.push_back(buf[n]);
}

// ── TLV ───────────────────────────────────────────────────────────────────
std::vector<uint8_t> encode_tlv(ASN1Tag tag, const std::vector<uint8_t>& value) {
    return encode_tlv(tag, value.data(), value.size());
}
std::vector<uint8_t> encode_tlv(ASN1Tag tag, const uint8_t* value, size_t len) {
    std::vector<uint8_t> out;
    out.push_back((uint8_t)tag);
    encode_length(out, len);
    if (len > 0) out.insert(out.end(), value, value + len);
    return out;
}

// ── 简单类型 ──────────────────────────────────────────────────────────────
std::vector<uint8_t> encode_integer(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> v;
    if (!bytes.empty() && (bytes[0] & 0x80)) v.push_back(0x00);
    append(v, bytes);
    while (v.size() > 1 && v[0] == 0x00 && !(v[1] & 0x80)) v.erase(v.begin());
    return encode_tlv(ASN1Tag::INTEGER, v);
}

// OID constants are already DER-encoded value bytes (e.g., {0x55,0x04,0x03} = 2.5.4.3)
// So encode_oid just wraps them in a TLV
std::vector<uint8_t> encode_oid(const uint8_t* oid, size_t len) {
    return encode_tlv(ASN1Tag::OID, oid, len);
}
std::vector<uint8_t> encode_oid(const std::vector<uint8_t>& oid) {
    return encode_tlv(ASN1Tag::OID, oid);
}

std::vector<uint8_t> encode_bit_string(const uint8_t* data, size_t len, uint8_t unused_bits) {
    std::vector<uint8_t> v; v.push_back(unused_bits);
    if (len > 0) v.insert(v.end(), data, data + len);
    return encode_tlv(ASN1Tag::BIT_STRING, v);
}
std::vector<uint8_t> encode_octet_string(const uint8_t* data, size_t len) {
    return encode_tlv(ASN1Tag::OCTET_STRING, data, len);
}
std::vector<uint8_t> encode_null() {
    return encode_tlv(ASN1Tag::NULL_TAG, nullptr, 0);
}
std::vector<uint8_t> encode_utc_time(uint64_t unix_time) {
    time_t t = (time_t)unix_time; struct tm* gmt = gmtime(&t);
    char buf[14];
    snprintf(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ",
             gmt->tm_year % 100, gmt->tm_mon + 1, gmt->tm_mday,
             gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
    return encode_tlv(ASN1Tag::UTCTime, (const uint8_t*)buf, 13);
}
std::vector<uint8_t> encode_printable_string(const std::string& s) {
    return encode_tlv(ASN1Tag::PRINTABLE_STRING, (const uint8_t*)s.data(), s.size());
}
std::vector<uint8_t> encode_ia5_string(const std::string& s) {
    return encode_tlv(ASN1Tag::IA5_STRING, (const uint8_t*)s.data(), s.size());
}
std::vector<uint8_t> encode_utf8_string(const std::string& s) {
    return encode_tlv(ASN1Tag::UTF8_STRING, (const uint8_t*)s.data(), s.size());
}

// ── 复合类型 ──────────────────────────────────────────────────────────────
std::vector<uint8_t> encode_sequence(const std::vector<uint8_t>& body) {
    return encode_tlv(ASN1Tag::SEQUENCE, body);
}
std::vector<uint8_t> encode_set(const std::vector<uint8_t>& body) {
    return encode_tlv(ASN1Tag::SET, body);
}
std::vector<uint8_t> encode_context(ASN1Tag tag, const std::vector<uint8_t>& value) {
    return encode_tlv(tag, value);
}

// ── Name ──────────────────────────────────────────────────────────────────
std::vector<uint8_t> encode_name(const DistinguishedName& dn) {
    std::vector<uint8_t> rdns;
    for (const auto& attr : dn) {
        std::vector<uint8_t> ava;
        append(ava, encode_oid(attr.oid));
        append(ava, encode_utf8_string(attr.value));
        append(rdns, encode_set(encode_sequence(ava)));
    }
    return encode_sequence(rdns);
}

// ── AlgorithmIdentifier ───────────────────────────────────────────────────
std::vector<uint8_t> encode_sig_algo(KeyType kt) {
    std::vector<uint8_t> inner;
    switch (kt) {
        case KeyType::RSA_2048: case KeyType::RSA_4096:
            append(inner, encode_oid(OID_SHA256_WITH_RSA, sizeof(OID_SHA256_WITH_RSA)));
            append(inner, encode_null());
            break;
        case KeyType::Ed25519:
            append(inner, encode_oid(OID_ED25519, sizeof(OID_ED25519)));
            break;
        case KeyType::Ed448:
            append(inner, encode_oid(OID_ED448, sizeof(OID_ED448)));
            break;
        case KeyType::ECDSA_P256:
            append(inner, encode_oid(OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256)));
            break;
        case KeyType::ECDSA_P384:
            append(inner, encode_oid(OID_ECDSA_WITH_SHA384, sizeof(OID_ECDSA_WITH_SHA384)));
            break;
        case KeyType::ECDSA_P521:
            append(inner, encode_oid(OID_ECDSA_WITH_SHA512, sizeof(OID_ECDSA_WITH_SHA512)));
            break;
        case KeyType::SM2:
            append(inner, encode_oid(OID_SM2_WITH_SM3, sizeof(OID_SM2_WITH_SM3)));
            break;
    }
    return encode_sequence(inner);
}

// ── SubjectPublicKeyInfo ──────────────────────────────────────────────────
std::vector<uint8_t> encode_spki(KeyType kt, const uint8_t* raw_key, size_t raw_key_len) {
    std::vector<uint8_t> alg_id_inner;
    switch (kt) {
        case KeyType::RSA_2048: case KeyType::RSA_4096:
            append(alg_id_inner, encode_oid(OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)));
            append(alg_id_inner, encode_null());
            break;
        case KeyType::Ed25519:
            append(alg_id_inner, encode_oid(OID_ED25519, sizeof(OID_ED25519)));
            break;
        case KeyType::Ed448:
            append(alg_id_inner, encode_oid(OID_ED448, sizeof(OID_ED448)));
            break;
        case KeyType::ECDSA_P256:
            append(alg_id_inner, encode_oid(OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY)));
            append(alg_id_inner, encode_oid(OID_EC_SECP256R1, sizeof(OID_EC_SECP256R1)));
            break;
        case KeyType::ECDSA_P384:
            append(alg_id_inner, encode_oid(OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY)));
            append(alg_id_inner, encode_oid(OID_EC_SECP384R1, sizeof(OID_EC_SECP384R1)));
            break;
        case KeyType::ECDSA_P521:
            append(alg_id_inner, encode_oid(OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY)));
            append(alg_id_inner, encode_oid(OID_EC_SECP521R1, sizeof(OID_EC_SECP521R1)));
            break;
        case KeyType::SM2:
            append(alg_id_inner, encode_oid(OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY)));
            append(alg_id_inner, encode_oid(OID_SM2, sizeof(OID_SM2)));
            break;
    }
    auto alg_id = encode_sequence(alg_id_inner);

    // Public key
    std::vector<uint8_t> pub_der;
    switch (kt) {
        case KeyType::RSA_2048: case KeyType::RSA_4096: {
            size_t n_len = raw_key_len - 3;
            std::vector<uint8_t> rsa_seq_body;
            append(rsa_seq_body, encode_integer(std::vector<uint8_t>(raw_key, raw_key + n_len)));
            uint8_t e[] = {0x01, 0x00, 0x01};
            append(rsa_seq_body, encode_integer(std::vector<uint8_t>(e, e + 3)));
            auto rsa_seq = encode_sequence(rsa_seq_body);
            pub_der = encode_bit_string(rsa_seq.data(), rsa_seq.size(), 0);
            break;
        }
        case KeyType::ECDSA_P256: case KeyType::ECDSA_P384: case KeyType::ECDSA_P521: case KeyType::SM2: {
            std::vector<uint8_t> point; point.push_back(0x04);
            point.insert(point.end(), raw_key, raw_key + raw_key_len);
            pub_der = encode_bit_string(point.data(), point.size(), 0);
            break;
        }
        case KeyType::Ed25519: case KeyType::Ed448:
            pub_der = encode_bit_string(raw_key, raw_key_len, 0);
            break;
    }

    std::vector<uint8_t> spki;
    append(spki, alg_id);
    append(spki, pub_der);
    return encode_sequence(spki);
}

// ── Extensions ────────────────────────────────────────────────────────────
std::vector<uint8_t> encode_extensions(const x509_cert& cert) {
    std::vector<uint8_t> exts;

    // BasicConstraints
    if (cert.basic_constraints) {
        std::vector<uint8_t> inner;
        if (cert.basic_constraints->ca) {
            inner.push_back(0x01); inner.push_back(0x01); inner.push_back(0xFF);
        }
        if (cert.basic_constraints->path_len >= 0) {
            int v = cert.basic_constraints->path_len;
            uint8_t buf[4]; int n = 0;
            if (v == 0) buf[n++] = 0;
            else while (v > 0) { buf[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
            std::vector<uint8_t> plv;
            while (n--) plv.push_back(buf[n]);
            append(inner, encode_integer(plv));
        }
        auto enc = encode_sequence(inner);
        std::vector<uint8_t> ext;
        append(ext, encode_oid(OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS)));
        ext.push_back(0x01); ext.push_back(0x01); ext.push_back(0xFF); // critical
        append(ext, encode_octet_string(enc.data(), enc.size()));
        append(exts, encode_sequence(ext));
    }

    // KeyUsage
    if (cert.key_usage) {
        uint16_t bits = cert.key_usage->bits;
        uint8_t ku_bytes[2]; int ku_len = 0;
        if (bits > 0xFF) { ku_bytes[0] = (uint8_t)(bits >> 8); ku_bytes[1] = (uint8_t)(bits & 0xFF); ku_len = 2; }
        else { ku_bytes[0] = (uint8_t)bits; ku_len = 1; }
        uint8_t last = ku_bytes[ku_len - 1];
        uint8_t unused = 0;
        if (last == 0) { unused = 8; ku_len--; }
        else { uint8_t m = 0x01; while ((last & m) == 0) { ++unused; m <<= 1; } }
        auto enc = encode_bit_string(ku_bytes, ku_len, unused);
        std::vector<uint8_t> ext;
        append(ext, encode_oid(OID_KEY_USAGE, sizeof(OID_KEY_USAGE)));
        ext.push_back(0x01); ext.push_back(0x01); ext.push_back(0xFF);
        append(ext, encode_octet_string(enc.data(), enc.size()));
        append(exts, encode_sequence(ext));
    }

    // ExtendedKeyUsage
    if (cert.ext_key_usage && !cert.ext_key_usage->usages.empty()) {
        std::vector<uint8_t> inner;
        for (auto u : cert.ext_key_usage->usages) {
            switch (u) {
                case ExtKeyUsage::SERVER_AUTH: append(inner, encode_oid(OID_EKU_SERVER_AUTH, sizeof(OID_EKU_SERVER_AUTH))); break;
                case ExtKeyUsage::CLIENT_AUTH: append(inner, encode_oid(OID_EKU_CLIENT_AUTH, sizeof(OID_EKU_CLIENT_AUTH))); break;
            }
        }
        auto enc = encode_sequence(inner);
        std::vector<uint8_t> ext;
        append(ext, encode_oid(OID_EXT_KEY_USAGE, sizeof(OID_EXT_KEY_USAGE)));
        append(ext, encode_octet_string(enc.data(), enc.size()));
        append(exts, encode_sequence(ext));
    }

    // SubjectAlternativeName
    if (cert.subject_alt_name && !cert.subject_alt_name->dns_names.empty()) {
        std::vector<uint8_t> inner;
        for (const auto& dns : cert.subject_alt_name->dns_names) {
            std::vector<uint8_t> gn; gn.push_back(0x82);
            encode_length(gn, dns.size());
            gn.insert(gn.end(), (const uint8_t*)dns.data(), (const uint8_t*)dns.data() + dns.size());
            append(inner, gn);
        }
        auto enc = encode_sequence(inner);
        std::vector<uint8_t> ext;
        append(ext, encode_oid(OID_SUBJECT_ALT_NAME, sizeof(OID_SUBJECT_ALT_NAME)));
        append(ext, encode_octet_string(enc.data(), enc.size()));
        append(exts, encode_sequence(ext));
    }

    // Raw (verbatim) extensions
    for (const auto& raw : cert.raw_extensions) {
        std::vector<uint8_t> ext;
        append(ext, encode_oid(raw.oid));
        if (raw.critical) { ext.push_back(0x01); ext.push_back(0x01); ext.push_back(0xFF); }
        append(ext, encode_octet_string(raw.extn_value.data(), raw.extn_value.size()));
        append(exts, encode_sequence(ext));
    }

    if (exts.empty()) return {};
    return encode_context(ASN1Tag::CONTEXT3, encode_sequence(exts));
}

// ── 解码辅助 ─────────────────────────────────────────────────────────────
bool TLV::is_constructed() const { return ((uint8_t)tag & 0x20) != 0; }

static size_t decode_length(const uint8_t* data, size_t len, size_t& offset) {
    if (offset >= len) return 0;
    uint8_t first = data[offset++];
    if (first < 0x80) return first;
    int num_bytes = first & 0x7F;
    if (num_bytes == 0 || offset + num_bytes > len) return 0;
    size_t result = 0;
    for (int i = 0; i < num_bytes; ++i) result = (result << 8) | data[offset++];
    return result;
}

std::optional<TLV> decode_tlv(const uint8_t* data, size_t len, size_t& offset) {
    if (offset >= len) return std::nullopt;
    ASN1Tag tag = (ASN1Tag)data[offset++];
    size_t value_len = decode_length(data, len, offset);
    if (value_len == 0 && data[offset - 1] != 0x00) return std::nullopt;
    if (offset + value_len > len) return std::nullopt;
    TLV tlv; tlv.tag = tag;
    tlv.value.assign(data + offset, data + offset + value_len);
    offset += value_len;
    return tlv;
}

// Internal decode helper (returns TLV with total_len, skips tag/length)
static std::optional<TLV> decode_tlv2(const uint8_t* data, size_t len, size_t& offset) {
    if (offset >= len) return std::nullopt;
    size_t start = offset;
    TLV tlv; tlv.tag = (ASN1Tag)data[offset++];
    size_t vlen = decode_length(data, len, offset);
    if (offset + vlen > len) return std::nullopt;
    tlv.value.assign(data + offset, data + offset + vlen);
    offset += vlen;
    tlv.total_len = offset - start;
    return tlv;
}

std::vector<uint8_t> tlv_to_integer(const TLV& tlv) { return tlv.value; }

std::vector<uint8_t> tlv_to_oid(const TLV& tlv) {
    if (tlv.value.empty()) return {};
    std::vector<uint8_t> oid;
    oid.push_back(tlv.value[0]);  // keep DER merged first byte (40*a+b), matches OID_* constants
    size_t i = 1;
    while (i < tlv.value.size()) {
        uint64_t comp = 0;
        while (i < tlv.value.size() && (tlv.value[i] & 0x80)) { comp = (comp << 7) | (tlv.value[i] & 0x7F); ++i; }
        if (i < tlv.value.size()) comp = (comp << 7) | tlv.value[i++];
        if (comp < 128) oid.push_back((uint8_t)comp);
        else {
            uint8_t buf[8]; int n = 0;
            for (uint64_t v = comp; v > 0; v /= 128) buf[n++] = (uint8_t)(v % 128);
            for (int k = n - 1; k >= 0; --k) oid.push_back(k > 0 ? (uint8_t)(buf[k] | 0x80) : buf[k]);  // base128 + 延续位
        }
    }
    return oid;
}

std::vector<uint8_t> tlv_to_bit_string(const TLV& tlv) {
    if (tlv.value.empty()) return {};
    return std::vector<uint8_t>(tlv.value.begin() + 1, tlv.value.end());
}
std::vector<uint8_t> tlv_to_octet_string(const TLV& tlv) { return tlv.value; }

std::optional<uint64_t> tlv_to_utc_time(const TLV& tlv) {
    if (tlv.value.size() < 12) return std::nullopt;
    std::string s((const char*)tlv.value.data(), tlv.value.size());
    int y, mo, d, h, mi, se;
    if (sscanf(s.c_str(), "%2d%2d%2d%2d%2d%2d", &y, &mo, &d, &h, &mi, &se) != 6) return std::nullopt;
    y += (y >= 50) ? 1900 : 2000;
    struct tm tm = {}; tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d;
    tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = se; tm.tm_isdst = -1;
#ifdef _WIN32
    return (uint64_t)_mkgmtime(&tm);
#else
    return (uint64_t)timegm(&tm);
#endif
}

std::string tlv_to_string(const TLV& tlv) {
    return std::string((const char*)tlv.value.data(), tlv.value.size());
}

bool oid_equal(const std::vector<uint8_t>& a, const uint8_t* b, size_t b_len) {
    return a.size() == b_len && memcmp(a.data(), b, b_len) == 0;
}
bool oid_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return a == b;
}

} // namespace der

// ═══════════════════════════════════════════════════════════════════════
//  to_der
// ═══════════════════════════════════════════════════════════════════════
std::vector<uint8_t> x509_cert::to_der() const {
    using namespace der;
    std::vector<uint8_t> tbs;

    // version (RFC 5280: 0=v1, 1=v2, 2=v3; v1 省略该字段)
    if (version > 0) {
        std::vector<uint8_t> v; v.push_back((uint8_t)version);
        auto ctx = encode_context(ASN1Tag::CONTEXT0, encode_integer(v));
        append(tbs, ctx);
    }

    // serialNumber, signature, issuer
    append(tbs, encode_integer(serial_number));
    append(tbs, encode_sig_algo(sign_key_type));
    append(tbs, encode_name(issuer));

    // validity
    std::vector<uint8_t> validity;
    append(validity, encode_utc_time(not_before));
    append(validity, encode_utc_time(not_after));
    append(tbs, encode_sequence(validity));

    // subject, SPKI
    append(tbs, encode_name(subject));
    append(tbs, encode_spki(key_type, public_key.data(), public_key.size()));

    // extensions
    if (version >= 2) {
        auto exts = encode_extensions(*this);
        if (!exts.empty()) append(tbs, exts);
    }

    // Certificate: SEQUENCE { tbs, sigAlg, sigValue }
    std::vector<uint8_t> body;
    append(body, encode_sequence(tbs));
    append(body, encode_sig_algo(sign_key_type));
    append(body, encode_bit_string(signature.data(), signature.size(), 0));

    return encode_sequence(body);
}

// ═══════════════════════════════════════════════════════════════════════

// DN parser helper
static DistinguishedName parse_dn(const std::vector<uint8_t>& dn_data) {
    using namespace der;
    DistinguishedName dn;
    size_t off = 0;
    while (off < dn_data.size()) {
        auto rdn = decode_tlv2(dn_data.data(), dn_data.size(), off);
        if (!rdn || rdn->tag != ASN1Tag::SET) break;
        size_t so = 0;
        auto ava = decode_tlv2(rdn->value.data(), rdn->value.size(), so);
        if (!ava || ava->tag != ASN1Tag::SEQUENCE) continue;
        size_t ao = 0;
        auto oid_tlv = decode_tlv2(ava->value.data(), ava->value.size(), ao);
        auto val_tlv = decode_tlv2(ava->value.data(), ava->value.size(), ao);
        if (oid_tlv && val_tlv && oid_tlv->tag == ASN1Tag::OID) {
            NameAttribute attr;
            // Store raw DER-encoded OID bytes (matching OID_CN etc. header constants)
            attr.oid = oid_tlv->value;
            attr.value = tlv_to_string(*val_tlv);
            dn.push_back(std::move(attr));
        }
    }
    return dn;
}

//  from_der
// ═══════════════════════════════════════════════════════════════════════
std::optional<x509_cert> x509_cert::from_der(const uint8_t* data, size_t len) {
    using namespace der;
    size_t off = 0;
    auto cert_tlv = decode_tlv2(data, len, off);
    if (!cert_tlv || cert_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;

    x509_cert cert;

    size_t inner_off = 0;
    // Save raw TBS for verification (includes the SEQUENCE tag+length)
    size_t tbs_start = inner_off;
    auto tbs_tlv = decode_tlv2(cert_tlv->value.data(), cert_tlv->value.size(), inner_off);
    if (!tbs_tlv || tbs_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    cert.tbs_raw.assign(cert_tlv->value.data() + tbs_start,
                        cert_tlv->value.data() + inner_off);
    auto sig_alg_tlv = decode_tlv2(cert_tlv->value.data(), cert_tlv->value.size(), inner_off);
    if (!sig_alg_tlv || sig_alg_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    auto sig_tlv = decode_tlv2(cert_tlv->value.data(), cert_tlv->value.size(), inner_off);
    if (!sig_tlv || sig_tlv->tag != ASN1Tag::BIT_STRING) return std::nullopt;

    cert.signature = tlv_to_bit_string(*sig_tlv);

    size_t tbs_off = 0;
    auto first = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
    if (!first) return std::nullopt;

    // version [0]?  (RFC 5280: 0=v1, 1=v2, 2=v3; v1 无该字段)
    cert.version = 0;  // 默认 v1，避免残留 builder 默认值 (v3) 导致重编码多出 version 字段
    if (first->tag == ASN1Tag::CONTEXT0) {
        size_t voff = 0;
        auto ver_tlv = decode_tlv2(first->value.data(), first->value.size(), voff);
        if (ver_tlv && ver_tlv->tag == ASN1Tag::INTEGER && !ver_tlv->value.empty())
            cert.version = (int)ver_tlv->value[0];
        first = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
        if (!first) return std::nullopt;
    }

    if (first->tag != ASN1Tag::INTEGER) return std::nullopt;
    cert.serial_number = first->value;

    auto tbs_sig = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
    if (!tbs_sig || tbs_sig->tag != ASN1Tag::SEQUENCE) return std::nullopt;

    auto issuer_tlv = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
    if (!issuer_tlv || issuer_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    cert.issuer = parse_dn(issuer_tlv->value);

    auto valid_tlv = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
    if (!valid_tlv || valid_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    { size_t voff = 0;
      auto nb = decode_tlv2(valid_tlv->value.data(), valid_tlv->value.size(), voff);
      if (nb) cert.not_before = tlv_to_utc_time(*nb).value_or(0);
      auto na = decode_tlv2(valid_tlv->value.data(), valid_tlv->value.size(), voff);
      if (na) cert.not_after = tlv_to_utc_time(*na).value_or(0); }

    auto subj_tlv = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
    if (!subj_tlv || subj_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    cert.subject = parse_dn(subj_tlv->value);

    auto spki_tlv = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
    if (!spki_tlv || spki_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;

    // Parse SPKI
    {   size_t soff = 0;
        auto alg_tlv = decode_tlv2(spki_tlv->value.data(), spki_tlv->value.size(), soff);
        if (!alg_tlv || alg_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
        size_t aoff = 0;
        auto oid_tlv = decode_tlv2(alg_tlv->value.data(), alg_tlv->value.size(), aoff);
        if (!oid_tlv || oid_tlv->tag != ASN1Tag::OID) return std::nullopt;
        auto algo_oid = oid_tlv->value; // raw DER-encoded OID bytes
        if (oid_equal(algo_oid, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)))
            cert.key_type = KeyType::RSA_2048;
        else if (oid_equal(algo_oid, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) {
            auto curve_tlv = decode_tlv2(alg_tlv->value.data(), alg_tlv->value.size(), aoff);
            cert.key_type = KeyType::ECDSA_P256;
            if (curve_tlv) {
                auto co = tlv_to_oid(*curve_tlv);
                if (oid_equal(co, OID_SM2, sizeof(OID_SM2))) cert.key_type = KeyType::SM2;
                else if (oid_equal(co, OID_EC_SECP384R1, sizeof(OID_EC_SECP384R1))) cert.key_type = KeyType::ECDSA_P384;
                else if (oid_equal(co, OID_EC_SECP521R1, sizeof(OID_EC_SECP521R1))) cert.key_type = KeyType::ECDSA_P521;
            }
        } else if (oid_equal(algo_oid, OID_ED25519, sizeof(OID_ED25519)))
            cert.key_type = KeyType::Ed25519;
        else if (oid_equal(algo_oid, OID_ED448, sizeof(OID_ED448)))
            cert.key_type = KeyType::Ed448;

        auto pub_tlv = decode_tlv2(spki_tlv->value.data(), spki_tlv->value.size(), soff);
        if (!pub_tlv || pub_tlv->tag != ASN1Tag::BIT_STRING) return std::nullopt;
        cert.public_key = tlv_to_bit_string(*pub_tlv);

        if ((cert.key_type == KeyType::ECDSA_P256 || cert.key_type == KeyType::ECDSA_P384 ||
             cert.key_type == KeyType::ECDSA_P521 || cert.key_type == KeyType::SM2)
            && !cert.public_key.empty() && cert.public_key[0] == 0x04)
            cert.public_key.erase(cert.public_key.begin());

        // RSA: decode RSAPublicKey SEQUENCE back to [n || e]
        if (cert.key_type == KeyType::RSA_2048 || cert.key_type == KeyType::RSA_4096) {
            size_t rsaoff = 0;
            auto rsa_seq = decode_tlv2(cert.public_key.data(), cert.public_key.size(), rsaoff);
            if (rsa_seq && rsa_seq->tag == ASN1Tag::SEQUENCE) {
                auto mod_tlv = decode_tlv2(rsa_seq->value.data(), rsa_seq->value.size(), rsaoff);
                auto exp_tlv = decode_tlv2(rsa_seq->value.data(), rsa_seq->value.size(), rsaoff);
                if (mod_tlv && exp_tlv && mod_tlv->tag == ASN1Tag::INTEGER && exp_tlv->tag == ASN1Tag::INTEGER) {
                    std::vector<uint8_t> raw;
                    const auto& m = mod_tlv->value;
                    size_t ms = (!m.empty() && m[0] == 0x00) ? 1 : 0;
                    raw.insert(raw.end(), m.begin() + ms, m.end());
                    append(raw, exp_tlv->value);
                    cert.public_key = std::move(raw);
                }
            }
        }
    }

    // extensions
    if (tbs_off < tbs_tlv->value.size()) {
        auto ext_tlv = decode_tlv2(tbs_tlv->value.data(), tbs_tlv->value.size(), tbs_off);
        if (ext_tlv && ext_tlv->tag == ASN1Tag::CONTEXT3) {
            size_t eoff = 0;
            auto ext_seq = decode_tlv2(ext_tlv->value.data(), ext_tlv->value.size(), eoff);
            if (ext_seq && ext_seq->tag == ASN1Tag::SEQUENCE) {
                size_t extoff = 0;
                while (extoff < ext_seq->value.size()) {
                    auto ext = decode_tlv2(ext_seq->value.data(), ext_seq->value.size(), extoff);
                    if (!ext || ext->tag != ASN1Tag::SEQUENCE) break;
                    size_t eioff = 0;
                    auto eoid_tlv = decode_tlv2(ext->value.data(), ext->value.size(), eioff);
                    if (!eoid_tlv || eoid_tlv->tag != ASN1Tag::OID) break;
                    auto eoid = eoid_tlv->value; // raw DER-encoded OID bytes
                    auto next = decode_tlv2(ext->value.data(), ext->value.size(), eioff);
                    bool critical = false;
                    if (next && next->tag == ASN1Tag::BOOLEAN) {
                        critical = !next->value.empty() && next->value[0] != 0;
                        next = decode_tlv2(ext->value.data(), ext->value.size(), eioff);
                    }
                    if (!next || next->tag != ASN1Tag::OCTET_STRING) break;

                    if (oid_equal(eoid, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS))) {
                        size_t bioff = 0;
                        auto bc_seq = decode_tlv2(next->value.data(), next->value.size(), bioff);
                        if (bc_seq) {
                            BasicConstraints bc;
                            size_t bo = 0; // 相对 SEQUENCE 内容的偏移
                            if (bo < bc_seq->value.size()) {
                                auto ca_tlv = decode_tlv2(bc_seq->value.data(), bc_seq->value.size(), bo);
                                if (ca_tlv && ca_tlv->tag == ASN1Tag::BOOLEAN)
                                    bc.ca = !ca_tlv->value.empty() && ca_tlv->value[0] != 0;
                            }
                            if (bo < bc_seq->value.size()) {
                                auto pl_tlv = decode_tlv2(bc_seq->value.data(), bc_seq->value.size(), bo);
                                if (pl_tlv && pl_tlv->tag == ASN1Tag::INTEGER && !pl_tlv->value.empty())
                                    bc.path_len = (int)pl_tlv->value[0];
                            }
                            cert.basic_constraints = bc;
                        }
                    } else if (oid_equal(eoid, OID_SUBJECT_ALT_NAME, sizeof(OID_SUBJECT_ALT_NAME))) {
                        size_t soff2 = 0;
                        auto san_seq = decode_tlv2(next->value.data(), next->value.size(), soff2);
                        if (san_seq && san_seq->tag == ASN1Tag::SEQUENCE) {
                            SubjectAlternativeName san;
                            size_t sioff = 0;
                            while (sioff < san_seq->value.size()) {
                                auto gn = decode_tlv2(san_seq->value.data(), san_seq->value.size(), sioff);
                                if (gn && gn->tag == (ASN1Tag)0x82)
                                    san.dns_names.push_back(std::string((const char*)gn->value.data(), gn->value.size()));
                            }
                            cert.subject_alt_name = san;
                        }
                    } else {
                        RawExtension raw;
                        raw.oid = eoid;
                        raw.critical = critical;
                        raw.extn_value = next->value;
                        cert.raw_extensions.push_back(std::move(raw));
                    }
                }
            }
        }
    }

    // sign key type from sig algo OID
    {   size_t saoff = 0;
        auto sa_oid_tlv = decode_tlv2(sig_alg_tlv->value.data(), sig_alg_tlv->value.size(), saoff);
        if (sa_oid_tlv) {
            auto sa_oid = tlv_to_oid(*sa_oid_tlv);
            if (oid_equal(sa_oid, OID_SHA256_WITH_RSA, sizeof(OID_SHA256_WITH_RSA))) cert.sign_key_type = KeyType::RSA_2048;
            else if (oid_equal(sa_oid, OID_SHA384_WITH_RSA, sizeof(OID_SHA384_WITH_RSA))) cert.sign_key_type = KeyType::RSA_4096;
            else if (oid_equal(sa_oid, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256))) cert.sign_key_type = KeyType::ECDSA_P256;
            else if (oid_equal(sa_oid, OID_ECDSA_WITH_SHA384, sizeof(OID_ECDSA_WITH_SHA384))) cert.sign_key_type = KeyType::ECDSA_P384;
            else if (oid_equal(sa_oid, OID_ECDSA_WITH_SHA512, sizeof(OID_ECDSA_WITH_SHA512))) cert.sign_key_type = KeyType::ECDSA_P521;
            else if (oid_equal(sa_oid, OID_ED25519, sizeof(OID_ED25519))) cert.sign_key_type = KeyType::Ed25519;
            else if (oid_equal(sa_oid, OID_ED448, sizeof(OID_ED448))) cert.sign_key_type = KeyType::Ed448;
            else if (oid_equal(sa_oid, OID_SM2_WITH_SM3, sizeof(OID_SM2_WITH_SM3))) cert.sign_key_type = KeyType::SM2;
        }
    }

    return cert;
}

std::optional<x509_cert> x509_cert::from_der(const std::vector<uint8_t>& der) {
    return from_der(der.data(), der.size());
}

// ═══════════════════════════════════════════════════════════════════════
//  x509_cert helpers
// ═══════════════════════════════════════════════════════════════════════
std::string x509_cert::common_name() const {
    for (const auto& a : subject)
        if (der::oid_equal(a.oid, OID_CN, sizeof(OID_CN))) return a.value;
    return "";
}
std::string x509_cert::issuer_name() const {
    for (const auto& a : issuer)
        if (der::oid_equal(a.oid, OID_CN, sizeof(OID_CN))) return a.value;
    return "";
}
bool x509_cert::is_valid_now() const { return is_valid_at((uint64_t)time(nullptr)); }
bool x509_cert::is_valid_at(uint64_t now_unix) const { return now_unix >= not_before && now_unix <= not_after; }
bool x509_cert::is_ca() const { return basic_constraints.has_value() && basic_constraints->ca; }
std::vector<std::string> x509_cert::dns_names() const {
    if (subject_alt_name) return subject_alt_name->dns_names;
    return {};
}

// ═══════════════════════════════════════════════════════════════════════
//  verify_signature
// ═══════════════════════════════════════════════════════════════════════
bool x509_cert::verify_signature(const x509_cert& issuer) const {
    // Prefer raw TBS saved by from_der (byte-identical to signing time),
    // avoids re-encoding differences from to_der(). Builder-native certs
    // (tbs_raw empty) fall back to re-encoding via to_der().
    std::vector<uint8_t> der;
    std::vector<uint8_t> tbs_copy;  // function-scope copy: cert_tlv dies at block end
    const uint8_t* tbs_data = nullptr;
    size_t tbs_len = 0;
    if (!tbs_raw.empty()) {
        tbs_data = tbs_raw.data();
        tbs_len = tbs_raw.size();
    } else {
        der = to_der();
        size_t off = 0;
        auto cert_tlv = der::decode_tlv2(der.data(), der.size(), off);
        if (!cert_tlv) return false;
        size_t inner_off = 0;
        auto tbs_tlv = der::decode_tlv2(cert_tlv->value.data(), cert_tlv->value.size(), inner_off);
        if (!tbs_tlv) return false;
        tbs_copy.assign(cert_tlv->value.data(), cert_tlv->value.data() + inner_off);
        tbs_data = tbs_copy.data();
        tbs_len = tbs_copy.size();
    }

    switch (sign_key_type) {
        case KeyType::RSA_2048: case KeyType::RSA_4096: {
            uint8_t hash[32];
            sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx, tbs_data, tbs_len); sha256_final(&ctx, hash);
            size_t n_len = issuer.public_key.size() > 3 ? issuer.public_key.size() - 3 : 256;
            rsa_bignum n = rsa_bignum::from_bytes(issuer.public_key.data(), n_len);
            rsa_bignum e = rsa_bignum::from_uint64(65537);
            rsa_bignum sig_bn = rsa_bignum::from_bytes(signature.data(), std::min(signature.size(), (size_t)256));
            rsa_bignum decrypted; bn_modpow(decrypted, sig_bn, e, n);
            uint8_t dec[256] = {}; decrypted.to_bytes(dec);
            if (dec[0] != 0x00 || dec[1] != 0x01) return false;
            size_t pos = 2;
            while (pos < 256 && dec[pos] == 0xFF) ++pos;
            if (pos >= 256 || dec[pos] != 0x00) return false;
            ++pos;
            static const uint8_t SHA256_DI[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
            size_t di_len = sizeof(SHA256_DI);
            if (pos + di_len + 32 > 256) return false;
            if (memcmp(dec + pos, SHA256_DI, di_len) != 0) return false;
            return memcmp(dec + pos + di_len, hash, 32) == 0;
        }
        case KeyType::Ed25519:
            return ed25519_verify(issuer.public_key.data(), tbs_data, tbs_len, signature.data());
        case KeyType::Ed448:
            return ed448_verify(issuer.public_key.data(), tbs_data, tbs_len, signature.data());
        case KeyType::ECDSA_P256: {
            uint8_t hash[32];
            sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx, tbs_data, tbs_len); sha256_final(&ctx, hash);
            return ecdsa_p256_verify(issuer.public_key.data(), hash, 32, signature.data());
        }
        case KeyType::ECDSA_P384: {
            uint8_t hash[48];
            sha512_ctx ctx; sha384_init(&ctx); sha512_update(&ctx, tbs_data, tbs_len); sha512_final(&ctx, hash);
            return ecdsa_p384_verify(issuer.public_key.data(), hash, 48, signature.data());
        }
        case KeyType::ECDSA_P521: {
            uint8_t hash[64];
            sha512_ctx ctx; sha512_init(&ctx); sha512_update(&ctx, tbs_data, tbs_len); sha512_final(&ctx, hash);
            return ecdsa_p521_verify(issuer.public_key.data(), hash, 64, signature.data());
        }
        case KeyType::SM2: {
            uint8_t hash[32];
            sm3_ctx ctx; sm3_init(&ctx); sm3_update(&ctx, tbs_data, tbs_len); sm3_final(&ctx, hash);
            return sm2_verify(issuer.public_key.data(), hash, 32, signature.data(), nullptr);
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
//  x509_builder
// ═══════════════════════════════════════════════════════════════════════
x509_cert x509_builder::build_and_sign(KeyType sign_key_type,
                                        const uint8_t* sign_priv_data,
                                        size_t sign_priv_len) {
    cert.sign_key_type = sign_key_type;
    cert.signature.clear();

    auto der = cert.to_der();
    size_t off = 0;
    auto cert_tlv = der::decode_tlv2(der.data(), der.size(), off);
    if (!cert_tlv) return cert;
    size_t inner_off = 0;
    auto tbs_tlv = der::decode_tlv2(cert_tlv->value.data(), cert_tlv->value.size(), inner_off);
    if (!tbs_tlv) return cert;

    const uint8_t* tbs_data = cert_tlv->value.data();
    size_t tbs_len = inner_off;

    uint8_t sig_buf[256]; size_t sig_len = 0;

    switch (sign_key_type) {
        case KeyType::RSA_2048: case KeyType::RSA_4096: {
            uint8_t hash[32];
            sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx, tbs_data, tbs_len); sha256_final(&ctx, hash);
            static const uint8_t SHA256_DI[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
            size_t di_len = sizeof(SHA256_DI);
            size_t pad_len = 256 - 3 - di_len - 32;
            uint8_t padded[256];
            padded[0] = 0x00; padded[1] = 0x01;
            memset(padded + 2, 0xFF, pad_len);
            padded[2 + pad_len] = 0x00;
            memcpy(padded + 2 + pad_len + 1, SHA256_DI, di_len);
            memcpy(padded + 2 + pad_len + 1 + di_len, hash, 32);
            rsa_bignum m = rsa_bignum::from_bytes(padded, 256);
            rsa_bignum d = rsa_bignum::from_bytes(sign_priv_data, sign_priv_len);
            size_t n_len = cert.public_key.size() > 3 ? cert.public_key.size() - 3 : 256;
            rsa_bignum n = rsa_bignum::from_bytes(cert.public_key.data(), n_len);
            rsa_bignum s; bn_modpow(s, m, d, n);
            sig_len = 256; s.to_bytes(sig_buf);
            break;
        }
        case KeyType::Ed25519:
            ed25519_sign(sign_priv_data, tbs_data, tbs_len, sig_buf); sig_len = 64; break;
        case KeyType::Ed448:
            ed448_sign(sign_priv_data, tbs_data, tbs_len, sig_buf); sig_len = 114; break;
        case KeyType::ECDSA_P256: {
            uint8_t hash[32];
            sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx, tbs_data, tbs_len); sha256_final(&ctx, hash);
            ecdsa_p256_sign(sign_priv_data, hash, 32, sig_buf); sig_len = 64; break;
        }
        case KeyType::ECDSA_P384: {
            uint8_t hash[48];
            sha512_ctx ctx; sha384_init(&ctx); sha512_update(&ctx, tbs_data, tbs_len); sha512_final(&ctx, hash);
            ecdsa_p384_sign(sign_priv_data, hash, 48, sig_buf); sig_len = 96; break;
        }
        case KeyType::ECDSA_P521: {
            uint8_t hash[64];
            sha512_ctx ctx; sha512_init(&ctx); sha512_update(&ctx, tbs_data, tbs_len); sha512_final(&ctx, hash);
            ecdsa_p521_sign(sign_priv_data, hash, 64, sig_buf); sig_len = 132; break;
        }
        case KeyType::SM2: {
            uint8_t hash[32];
            sm3_ctx ctx; sm3_init(&ctx); sm3_update(&ctx, tbs_data, tbs_len); sm3_final(&ctx, hash);
            sm2_sign(sign_priv_data, hash, 32, sig_buf, nullptr); sig_len = 64; break;
        }
    }

    cert.signature.assign(sig_buf, sig_buf + sig_len);
    return cert;
}

// ═══════════════════════════════════════════════════════════════════════
//  Chain verification
// ═══════════════════════════════════════════════════════════════════════
verify_result x509_verify_chain(const std::vector<x509_cert>& chain, uint64_t now_unix) {
    verify_result r;
    if (chain.empty()) { r.error = "empty chain"; return r; }
    if (now_unix == 0) now_unix = (uint64_t)time(nullptr);

    for (size_t i = 0; i < chain.size(); ++i) {
        if (!chain[i].is_valid_at(now_unix)) { r.error = "expired"; return r; }
        if (i + 1 < chain.size()) {
            if (!chain[i].verify_signature(chain[i + 1])) { r.error = "sig fail"; return r; }
        } else {
            if (!chain[i].is_ca()) { r.error = "root not CA"; return r; }
            if (!chain[i].verify_signature(chain[i])) { r.error = "root self-sig fail"; return r; }
        }
    }
    r.success = true;
    return r;
}


// ═══════════════════════════════════════════════════════════════════════
//  PEM 编解码
// ═══════════════════════════════════════════════════════════════════════
namespace {

/// 提取 PEM 块内的 base64 文本并解码为 DER
std::optional<std::vector<uint8_t>> pem_decode_block(const std::string& pem,
                                                     const char* label) {
    std::string begin = std::string("-----BEGIN ") + label + "-----";
    std::string end   = std::string("-----END ") + label + "-----";
    auto b = pem.find(begin);
    if (b == std::string::npos) return std::nullopt;
    auto e = pem.find(end, b + begin.size());
    if (e == std::string::npos) return std::nullopt;
    std::string b64 = pem.substr(b + begin.size(), e - (b + begin.size()));
    // 移除 PEM 中的空白字符
    std::string clean;
    clean.reserve(b64.size());
    for (char c : b64)
        if (!std::isspace((unsigned char)c)) clean.push_back(c);
    return jpssl::base64_decode(clean);
}

/// 将 DER 编码为 PEM 文本（每 64 字符换行）
std::string pem_encode_block(const std::vector<uint8_t>& der, const char* label) {
    std::string b64 = jpssl::base64_encode(der.data(), der.size());
    std::string out = std::string("-----BEGIN ") + label + "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64)
        out += b64.substr(i, 64) + "\n";
    out += std::string("-----END ") + label + "-----\n";
    return out;
}

/// 从 PEM 文本中找出首个匹配 label 的块，返回其 DER
std::optional<std::vector<uint8_t>> pem_extract_any(const std::string& pem,
                                                     const char** labels,
                                                     size_t n_labels) {
    for (size_t i = 0; i < n_labels; ++i) {
        auto der = pem_decode_block(pem, labels[i]);
        if (der) return der;
    }
    return std::nullopt;
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  加密私钥 PEM 解析 (PBES2 / RFC 8018)
// ═══════════════════════════════════════════════════════════════════════
namespace {

// OIDs (DER-encoded value bytes)
// PBES2     1.2.840.113549.1.5.13
// PBKDF2    1.2.840.113549.1.5.12
// hmacSHA256 1.2.840.113549.2.9
// aes128CBC 2.16.840.1.101.3.4.1.2
// aes256CBC 2.16.840.1.101.3.4.1.42
inline const uint8_t OID_PBES2[]     = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0D};
inline const uint8_t OID_PBKDF2[]    = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x05,0x0C};
inline const uint8_t OID_HMAC_SHA256[] = {0x2A,0x86,0x48,0x86,0xF7,0x0D,0x02,0x09};
inline const uint8_t OID_AES128_CBC[] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02};
inline const uint8_t OID_AES256_CBC[] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2A};

/// PBKDF2-HMAC-SHA256 (RFC 2898 §5.2)
/// 输出 dk_len 字节派生密钥
bool pbkdf2_hmac_sha256(const uint8_t* password, size_t pw_len,
                        const uint8_t* salt, size_t salt_len,
                        uint32_t iterations, uint8_t* dk, size_t dk_len) {
    if (iterations == 0) return false;
    const size_t hlen = 32;
    // RFC 2898 §5.2:
    //   U_1 = PRF(P, S || INT_32_BE(block))
    //   U_n = PRF(P, U_{n-1})
    //   T_i = U_1 ^ U_2 ^ ... ^ U_c
    // 注意: U_n 的输入是 U_{n-1}（原始值），不是已累积的 T。
    std::vector<uint8_t> u(hlen), t(hlen), tmp(salt_len + 4), out(hlen);
    for (uint32_t block = 1; dk_len > 0; ++block) {
        memcpy(tmp.data(), salt, salt_len);
        for (int i = 3; i >= 0; --i) tmp[salt_len + 3 - i] = (uint8_t)(block >> (i * 8));
        hmac_sha256(password, pw_len, tmp.data(), tmp.size(), u.data());
        memcpy(t.data(), u.data(), hlen);
        for (uint32_t it = 1; it < iterations; ++it) {
            // U_n = PRF(P, U_{n-1})：输入必须是上一轮原始 U，而非 t
            hmac_sha256(password, pw_len, u.data(), hlen, out.data());
            memcpy(u.data(), out.data(), hlen);
            for (size_t j = 0; j < hlen; ++j) t[j] ^= u[j];
        }
        size_t n = dk_len < hlen ? dk_len : hlen;
        memcpy(dk, t.data(), n);
        dk += n; dk_len -= n;
    }
    return true;
}

/// AES-CBC 解密（PKCS#7 padding 去除）
/// cipher_len 必须为 16 的倍数
std::optional<std::vector<uint8_t>> aes_cbc_decrypt(const uint8_t* key, size_t key_len,
                                                    const uint8_t* iv,
                                                    const uint8_t* cipher, size_t cipher_len) {
    if (cipher_len == 0 || cipher_len % 16 != 0) return std::nullopt;
    if (key_len != 16 && key_len != 32) return std::nullopt;
    aes_context ctx;
    if (key_len == 16) ctx.init(std::span<const uint8_t, 16>(key, 16));
    else               ctx.init(std::span<const uint8_t, 32>(key, 32));

    std::vector<uint8_t> out(cipher_len);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < cipher_len; off += 16) {
        uint8_t dec[16];
        aes_decrypt_block(ctx, cipher + off, dec);
        for (int i = 0; i < 16; ++i) out[off + i] = dec[i] ^ prev[i];
        memcpy(prev, cipher + off, 16);
    }
    // PKCS#7 padding
    if (out.empty()) return std::nullopt;
    uint8_t pad = out.back();
    if (pad == 0 || pad > 16 || pad > out.size()) return std::nullopt;
    for (size_t i = out.size() - pad; i < out.size(); ++i)
        if (out[i] != pad) return std::nullopt;
    out.resize(out.size() - pad);
    return out;
}

/// 解析 PBES2 EncryptedPrivateKeyInfo 并解密
///   SEQUENCE {
///     SEQUENCE {                    -- encryptionAlgorithm
///       OID pbes2,
///       SEQUENCE {
///         SEQUENCE {                -- keyDerivationFunc
///           OID pbkdf2,
///           SEQUENCE { OCTET STRING salt, INTEGER iterations, [prf] }
///         },
///         SEQUENCE {                -- encryptionScheme
///           OID aes-cbc, OCTET STRING iv
///         }
///       }
///     },
///     OCTET STRING encryptedData
///   }
std::optional<std::vector<uint8_t>> pbes2_decrypt(const std::vector<uint8_t>& der,
                                                  const std::string& password) {
    using namespace der;
    size_t off = 0;
    auto outer = decode_tlv2(der.data(), der.size(), off);
    if (!outer || outer->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t ooff = 0;
    auto alg_seq = decode_tlv2(outer->value.data(), outer->value.size(), ooff);
    if (!alg_seq || alg_seq->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t aoff = 0;
    auto pbes2_oid = decode_tlv2(alg_seq->value.data(), alg_seq->value.size(), aoff);
    if (!pbes2_oid || pbes2_oid->tag != ASN1Tag::OID) return std::nullopt;
    if (!oid_equal(pbes2_oid->value, OID_PBES2, sizeof(OID_PBES2))) return std::nullopt;
    auto params = decode_tlv2(alg_seq->value.data(), alg_seq->value.size(), aoff);
    if (!params || params->tag != ASN1Tag::SEQUENCE) return std::nullopt;

    // keyDerivationFunc
    size_t poff = 0;
    auto kdf = decode_tlv2(params->value.data(), params->value.size(), poff);
    if (!kdf || kdf->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t koff = 0;
    auto kdf_oid = decode_tlv2(kdf->value.data(), kdf->value.size(), koff);
    if (!kdf_oid || kdf_oid->tag != ASN1Tag::OID) return std::nullopt;
    if (!oid_equal(kdf_oid->value, OID_PBKDF2, sizeof(OID_PBKDF2))) return std::nullopt;
    auto kdf_params = decode_tlv2(kdf->value.data(), kdf->value.size(), koff);
    if (!kdf_params || kdf_params->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t kpoff = 0;
    auto salt_tlv = decode_tlv2(kdf_params->value.data(), kdf_params->value.size(), kpoff);
    if (!salt_tlv || salt_tlv->tag != ASN1Tag::OCTET_STRING) return std::nullopt;
    auto iter_tlv = decode_tlv2(kdf_params->value.data(), kdf_params->value.size(), kpoff);
    if (!iter_tlv || iter_tlv->tag != ASN1Tag::INTEGER || iter_tlv->value.empty()) return std::nullopt;
    uint32_t iterations = 0;
    for (uint8_t b : iter_tlv->value) iterations = (iterations << 8) | b;

    // encryptionScheme
    auto scheme = decode_tlv2(params->value.data(), params->value.size(), poff);
    if (!scheme || scheme->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t soff = 0;
    auto scheme_oid = decode_tlv2(scheme->value.data(), scheme->value.size(), soff);
    if (!scheme_oid || scheme_oid->tag != ASN1Tag::OID) return std::nullopt;
    auto iv_tlv = decode_tlv2(scheme->value.data(), scheme->value.size(), soff);
    if (!iv_tlv || iv_tlv->tag != ASN1Tag::OCTET_STRING || iv_tlv->value.size() != 16) return std::nullopt;

    // encryptedData
    auto data_tlv = decode_tlv2(outer->value.data(), outer->value.size(), ooff);
    if (!data_tlv || data_tlv->tag != ASN1Tag::OCTET_STRING) return std::nullopt;

    size_t key_len;
    if (oid_equal(scheme_oid->value, OID_AES128_CBC, sizeof(OID_AES128_CBC))) key_len = 16;
    else if (oid_equal(scheme_oid->value, OID_AES256_CBC, sizeof(OID_AES256_CBC))) key_len = 32;
    else return std::nullopt;

    std::vector<uint8_t> key(key_len);
    if (!pbkdf2_hmac_sha256((const uint8_t*)password.data(), password.size(),
                            salt_tlv->value.data(), salt_tlv->value.size(),
                            iterations, key.data(), key.size()))
        return std::nullopt;
    return aes_cbc_decrypt(key.data(), key.size(), iv_tlv->value.data(),
                           data_tlv->value.data(), data_tlv->value.size());
}

} // anonymous namespace

// ── x509_cert: PEM 读取 ──────────────────────────────────────────────────
std::optional<x509_cert> x509_cert::from_pem(const std::string& pem) {
    auto der = pem_decode_block(pem, "CERTIFICATE");
    if (!der) return std::nullopt;
    return from_der(*der);
}
std::optional<x509_cert> x509_cert::from_pem(const char* data, size_t len) {
    return from_pem(std::string(data, len));
}

std::string x509_cert::to_pem() const {
    return pem_encode_block(to_der(), "CERTIFICATE");
}

// ═══════════════════════════════════════════════════════════════════════
//  私钥解析 (PKCS#8 / PKCS#1 RSA / SEC1 EC / RFC 8410)
// ═══════════════════════════════════════════════════════════════════════
namespace {

/// 解析 PKCS#1 RSAPrivateKey: 提取 d (第 4 个 INTEGER) 与 n||e 公钥
std::optional<private_key> parse_pkcs1_rsa(const std::vector<uint8_t>& der) {
    using namespace der;
    size_t off = 0;
    auto seq = decode_tlv2(der.data(), der.size(), off);
    if (!seq || seq->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t ioff = 0;
    std::vector<uint8_t> n, e, d;
    int idx = 0;
    while (ioff < seq->value.size() && idx < 4) {
        auto it = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
        if (!it || it->tag != ASN1Tag::INTEGER) return std::nullopt;
        auto bytes = it->value;
        if (!bytes.empty() && bytes[0] == 0x00) bytes.erase(bytes.begin());
        if (idx == 1) n = std::move(bytes);
        else if (idx == 2) e = std::move(bytes);
        else if (idx == 3) d = std::move(bytes);
        ++idx;
    }
    if (idx < 4 || n.empty() || e.empty() || d.empty()) return std::nullopt;

    private_key key;
    key.key_type = (n.size() <= 256) ? KeyType::RSA_2048 : KeyType::RSA_4096;
    // d 固定 256/512 字节
    size_t dsz = (key.key_type == KeyType::RSA_2048) ? 256 : 512;
    key.priv.assign(dsz, 0);
    if (d.size() <= dsz) memcpy(key.priv.data() + dsz - d.size(), d.data(), d.size());
    else return std::nullopt;
    // 公钥: n(256) || e(3) 与 x509 格式一致
    key.pub.assign(dsz, 0);
    if (n.size() <= dsz) memcpy(key.pub.data() + dsz - n.size(), n.data(), n.size());
    else return std::nullopt;
    // e 通常 0x010001 (3 bytes)
    std::vector<uint8_t> e3 = e;
    while (e3.size() < 3) e3.insert(e3.begin(), 0x00);
    if (e3.size() > 3) return std::nullopt;
    key.pub.insert(key.pub.end(), e3.begin(), e3.end());
    return key;
}

/// 解析 SEC1 ECPrivateKey（可能带 curve OID 上下文和 [1] 公钥）
/// der: ECPrivateKey 整个 DER
/// curve_oid_hint: 若外部 AlgorithmIdentifier 已提供曲线 OID，可为 nullptr
std::optional<private_key> parse_sec1_ec(const std::vector<uint8_t>& der,
                                         const std::vector<uint8_t>* curve_oid_hint) {
    using namespace der;
    size_t off = 0;
    auto seq = decode_tlv2(der.data(), der.size(), off);
    if (!seq || seq->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t ioff = 0;
    // version INTEGER (optional tolerate)
    auto ver = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
    if (!ver) return std::nullopt;
    if (ver->tag == ASN1Tag::INTEGER) {
        auto priv_tlv = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
        if (!priv_tlv || priv_tlv->tag != ASN1Tag::OCTET_STRING) return std::nullopt;

        private_key key;
        key.priv = priv_tlv->value;
        // 剩余字段: [0] curve, [1] pub
        std::vector<uint8_t> curve_oid;
        while (ioff < seq->value.size()) {
            auto ctx = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
            if (!ctx) break;
            if (ctx->tag == ASN1Tag::CONTEXT0) {
                size_t co = 0;
                auto oid_tlv = decode_tlv2(ctx->value.data(), ctx->value.size(), co);
                if (oid_tlv && oid_tlv->tag == ASN1Tag::OID)
                    curve_oid = tlv_to_oid(*oid_tlv);
            } else if (ctx->tag == ASN1Tag::CONTEXT1) {
                size_t po = 0;
                auto bit_tlv = decode_tlv2(ctx->value.data(), ctx->value.size(), po);
                if (bit_tlv && bit_tlv->tag == ASN1Tag::BIT_STRING) {
                    key.pub = tlv_to_bit_string(*bit_tlv);
                    if (!key.pub.empty() && key.pub[0] == 0x04)
                        key.pub.erase(key.pub.begin());
                }
            }
        }
        if (curve_oid.empty() && curve_oid_hint) curve_oid = *curve_oid_hint;

        // 判定曲线类型
        if (oid_equal(curve_oid, OID_SM2, sizeof(OID_SM2))) key.key_type = KeyType::SM2;
        else if (oid_equal(curve_oid, OID_EC_SECP384R1, sizeof(OID_EC_SECP384R1))) key.key_type = KeyType::ECDSA_P384;
        else if (oid_equal(curve_oid, OID_EC_SECP521R1, sizeof(OID_EC_SECP521R1))) key.key_type = KeyType::ECDSA_P521;
        else key.key_type = KeyType::ECDSA_P256;  // 默认 P-256
        return key;
    }
    return std::nullopt;
}

/// 解析 PKCS#8 PrivateKeyInfo
/// der: 整个 PKCS#8 DER
std::optional<private_key> parse_pkcs8(const std::vector<uint8_t>& der) {
    using namespace der;
    size_t off = 0;
    auto seq = decode_tlv2(der.data(), der.size(), off);
    if (!seq || seq->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t ioff = 0;
    auto ver = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
    if (!ver || ver->tag != ASN1Tag::INTEGER) return std::nullopt;
    auto alg_tlv = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
    if (!alg_tlv || alg_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    size_t aoff = 0;
    auto oid_tlv = decode_tlv2(alg_tlv->value.data(), alg_tlv->value.size(), aoff);
    if (!oid_tlv || oid_tlv->tag != ASN1Tag::OID) return std::nullopt;
    auto algo_oid = tlv_to_oid(*oid_tlv);
    auto key_tlv = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
    if (!key_tlv || key_tlv->tag != ASN1Tag::OCTET_STRING) return std::nullopt;

    if (oid_equal(algo_oid, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION))) {
        // OCTET STRING 内是 PKCS#1 RSAPrivateKey
        return parse_pkcs1_rsa(key_tlv->value);
    }
    if (oid_equal(algo_oid, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) {
        // 提取曲线 OID（AlgorithmIdentifier 第二个元素）
        std::vector<uint8_t> curve_oid;
        auto curve_tlv = decode_tlv2(alg_tlv->value.data(), alg_tlv->value.size(), aoff);
        if (curve_tlv && curve_tlv->tag == ASN1Tag::OID)
            curve_oid = tlv_to_oid(*curve_tlv);
        // OCTET STRING 内是 SEC1 ECPrivateKey
        return parse_sec1_ec(key_tlv->value, curve_oid.empty() ? nullptr : &curve_oid);
    }
    if (oid_equal(algo_oid, OID_ED25519, sizeof(OID_ED25519))) {
        private_key key;
        key.key_type = KeyType::Ed25519;
        // RFC 8410: privateKey = OCTET STRING 内是 32 字节 seed（可能带 [0] 包裹）
        const auto& inner = key_tlv->value;
        size_t ko = 0;
        std::vector<uint8_t> seed;
        auto t = decode_tlv2(inner.data(), inner.size(), ko);
        if (t && t->tag == ASN1Tag::CONTEXT0) {
            size_t z = 0;
            auto o = decode_tlv2(t->value.data(), t->value.size(), z);
            if (o && o->tag == ASN1Tag::OCTET_STRING) seed = o->value;
            else seed = t->value;
        } else if (t && t->tag == ASN1Tag::OCTET_STRING) {
            seed = t->value;
        } else {
            seed = inner;
        }
        if (seed.size() != 32) return std::nullopt;
        key.priv.assign(64, 0);
        memcpy(key.priv.data(), seed.data(), 32);
        key.pub.resize(32);
        jpssl::ed25519_derive_public_key(seed.data(), key.pub.data());
        memcpy(key.priv.data() + 32, key.pub.data(), 32);  // seed || pub
        return key;
    }
    if (oid_equal(algo_oid, OID_ED448, sizeof(OID_ED448))) {
        private_key key;
        key.key_type = KeyType::Ed448;
        const auto& inner = key_tlv->value;
        size_t ko = 0;
        std::vector<uint8_t> seed;
        auto t = decode_tlv2(inner.data(), inner.size(), ko);
        if (t && t->tag == ASN1Tag::CONTEXT0) {
            size_t z = 0;
            auto o = decode_tlv2(t->value.data(), t->value.size(), z);
            if (o && o->tag == ASN1Tag::OCTET_STRING) seed = o->value;
            else seed = t->value;
        } else if (t && t->tag == ASN1Tag::OCTET_STRING) {
            seed = t->value;
        } else {
            seed = inner;
        }
        if (seed.size() != 57) return std::nullopt;
        key.priv = seed;  // 库内 ed448 私钥格式 = 57 字节 seed
        key.pub.resize(57);
        jpssl::ed448_keygen(key.pub.data(), seed.data());
        return key;
    }
    return std::nullopt;
}

} // anonymous namespace

std::optional<private_key> private_key::from_der(const uint8_t* data, size_t len) {
    return from_der(std::vector<uint8_t>(data, data + len));
}
std::optional<private_key> private_key::from_der(const std::vector<uint8_t>& der) {
    using namespace der;
    // 顶层 SEQUENCE
    size_t off = 0;
    auto seq = decode_tlv2(der.data(), der.size(), off);
    if (!seq || seq->tag != ASN1Tag::SEQUENCE) return std::nullopt;

    size_t ioff = 0;
    auto first = decode_tlv2(seq->value.data(), seq->value.size(), ioff);
    if (!first) return std::nullopt;

    // 分发依据顶层结构:
    //   PKCS#8:  SEQUENCE { INTEGER 0, SEQUENCE alg, OCTET STRING key }
    //   PKCS#1:  SEQUENCE { INTEGER 0, INTEGER n, INTEGER e, ... }
    //   SEC1:    SEQUENCE { INTEGER 1, OCTET STRING priv, ... }
    if (first->tag == ASN1Tag::INTEGER) {
        size_t tmp = ioff;
        auto second = decode_tlv2(seq->value.data(), seq->value.size(), tmp);
        if (!second) return std::nullopt;
        if (second->tag == ASN1Tag::SEQUENCE) {
            // PKCS#8: version + AlgorithmIdentifier
            auto key = parse_pkcs8(der);
            if (key) return key;
            return std::nullopt;
        }
        if (second->tag == ASN1Tag::INTEGER) {
            // PKCS#1 RSA: version + n + e + d ...
            auto key = parse_pkcs1_rsa(der);
            if (key) return key;
            return std::nullopt;
        }
        if (second->tag == ASN1Tag::OCTET_STRING) {
            // SEC1 EC: version(1) + privateKey OCTET STRING ...
            auto key = parse_sec1_ec(der, nullptr);
            if (key) return key;
            return std::nullopt;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<private_key> private_key::from_pem(const std::string& pem) {
    static const char* labels[] = {"PRIVATE KEY", "RSA PRIVATE KEY",
                                   "EC PRIVATE KEY", "ED25519 PRIVATE KEY",
                                   "ED448 PRIVATE KEY"};
    auto der = pem_extract_any(pem, labels, sizeof(labels)/sizeof(labels[0]));
    if (!der) return std::nullopt;
    return from_der(*der);
}
std::optional<private_key> private_key::from_pem(const char* data, size_t len) {
    return from_pem(std::string(data, len));
}

std::optional<private_key> private_key::from_pem_encrypted(const std::string& pem,
                                                           const std::string& password) {
    auto der = pem_decode_block(pem, "ENCRYPTED PRIVATE KEY");
    if (!der) return std::nullopt;
    auto plain = pbes2_decrypt(*der, password);
    if (!plain) return std::nullopt;
    return from_der(*plain);
}
std::optional<private_key> private_key::from_pem_encrypted(const char* data, size_t len,
                                                           const std::string& password) {
    return from_pem_encrypted(std::string(data, len), password);
}

// ═══════════════════════════════════════════════════════════════════════
//  PKCS#10 CSR 解析
// ═══════════════════════════════════════════════════════════════════════
std::optional<csr> csr::from_der(const uint8_t* data, size_t len) {
    using namespace der;
    size_t off = 0;
    auto outer = decode_tlv2(data, len, off);
    if (!outer || outer->tag != ASN1Tag::SEQUENCE) return std::nullopt;

    csr out;
    size_t ooff = 0;
    // CertificationRequestInfo
    size_t info_start = ooff;
    auto info_tlv = decode_tlv2(outer->value.data(), outer->value.size(), ooff);
    if (!info_tlv || info_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    out.tbs_raw.assign(outer->value.data() + info_start,
                       outer->value.data() + ooff);

    size_t ioff = 0;
    auto ver = decode_tlv2(info_tlv->value.data(), info_tlv->value.size(), ioff);
    if (!ver || ver->tag != ASN1Tag::INTEGER) return std::nullopt;

    auto subj_tlv = decode_tlv2(info_tlv->value.data(), info_tlv->value.size(), ioff);
    if (!subj_tlv || subj_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    out.subject = parse_dn(subj_tlv->value);

    auto spki_tlv = decode_tlv2(info_tlv->value.data(), info_tlv->value.size(), ioff);
    if (!spki_tlv || spki_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;

    // 解析 SPKI（与证书一致）
    {   size_t soff = 0;
        auto alg_tlv = decode_tlv2(spki_tlv->value.data(), spki_tlv->value.size(), soff);
        if (!alg_tlv || alg_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
        size_t aoff = 0;
        auto oid_tlv = decode_tlv2(alg_tlv->value.data(), alg_tlv->value.size(), aoff);
        if (!oid_tlv || oid_tlv->tag != ASN1Tag::OID) return std::nullopt;
        auto algo_oid = oid_tlv->value;
        if (oid_equal(algo_oid, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)))
            out.key_type = KeyType::RSA_2048;
        else if (oid_equal(algo_oid, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) {
            auto curve_tlv = decode_tlv2(alg_tlv->value.data(), alg_tlv->value.size(), aoff);
            out.key_type = KeyType::ECDSA_P256;
            if (curve_tlv) {
                auto co = tlv_to_oid(*curve_tlv);
                if (oid_equal(co, OID_SM2, sizeof(OID_SM2))) out.key_type = KeyType::SM2;
                else if (oid_equal(co, OID_EC_SECP384R1, sizeof(OID_EC_SECP384R1))) out.key_type = KeyType::ECDSA_P384;
                else if (oid_equal(co, OID_EC_SECP521R1, sizeof(OID_EC_SECP521R1))) out.key_type = KeyType::ECDSA_P521;
            }
        } else if (oid_equal(algo_oid, OID_ED25519, sizeof(OID_ED25519)))
            out.key_type = KeyType::Ed25519;
        else if (oid_equal(algo_oid, OID_ED448, sizeof(OID_ED448)))
            out.key_type = KeyType::Ed448;

        auto pub_tlv = decode_tlv2(spki_tlv->value.data(), spki_tlv->value.size(), soff);
        if (!pub_tlv || pub_tlv->tag != ASN1Tag::BIT_STRING) return std::nullopt;
        out.public_key = tlv_to_bit_string(*pub_tlv);
        if ((out.key_type == KeyType::ECDSA_P256 || out.key_type == KeyType::ECDSA_P384 ||
             out.key_type == KeyType::ECDSA_P521 || out.key_type == KeyType::SM2)
            && !out.public_key.empty() && out.public_key[0] == 0x04)
            out.public_key.erase(out.public_key.begin());
        // RSA: 还原为 [n||e]
        if (out.key_type == KeyType::RSA_2048 || out.key_type == KeyType::RSA_4096) {
            size_t rsaoff = 0;
            auto rsa_seq = decode_tlv2(out.public_key.data(), out.public_key.size(), rsaoff);
            if (rsa_seq && rsa_seq->tag == ASN1Tag::SEQUENCE) {
                auto mod_tlv = decode_tlv2(rsa_seq->value.data(), rsa_seq->value.size(), rsaoff);
                auto exp_tlv = decode_tlv2(rsa_seq->value.data(), rsa_seq->value.size(), rsaoff);
                if (mod_tlv && exp_tlv && mod_tlv->tag == ASN1Tag::INTEGER && exp_tlv->tag == ASN1Tag::INTEGER) {
                    std::vector<uint8_t> raw;
                    const auto& m = mod_tlv->value;
                    size_t ms = (!m.empty() && m[0] == 0x00) ? 1 : 0;
                    raw.insert(raw.end(), m.begin() + ms, m.end());
                    append(raw, exp_tlv->value);
                    out.public_key = std::move(raw);
                }
            }
        }
    }

    // signatureAlgorithm + signature
    auto sig_alg_tlv = decode_tlv2(outer->value.data(), outer->value.size(), ooff);
    if (!sig_alg_tlv || sig_alg_tlv->tag != ASN1Tag::SEQUENCE) return std::nullopt;
    {   size_t saoff = 0;
        auto sa_oid_tlv = decode_tlv2(sig_alg_tlv->value.data(), sig_alg_tlv->value.size(), saoff);
        if (sa_oid_tlv) {
            auto sa_oid = tlv_to_oid(*sa_oid_tlv);
            if (oid_equal(sa_oid, OID_SHA256_WITH_RSA, sizeof(OID_SHA256_WITH_RSA))) out.sign_key_type = KeyType::RSA_2048;
            else if (oid_equal(sa_oid, OID_SHA384_WITH_RSA, sizeof(OID_SHA384_WITH_RSA))) out.sign_key_type = KeyType::RSA_4096;
            else if (oid_equal(sa_oid, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256))) out.sign_key_type = KeyType::ECDSA_P256;
            else if (oid_equal(sa_oid, OID_ECDSA_WITH_SHA384, sizeof(OID_ECDSA_WITH_SHA384))) out.sign_key_type = KeyType::ECDSA_P384;
            else if (oid_equal(sa_oid, OID_ECDSA_WITH_SHA512, sizeof(OID_ECDSA_WITH_SHA512))) out.sign_key_type = KeyType::ECDSA_P521;
            else if (oid_equal(sa_oid, OID_ED25519, sizeof(OID_ED25519))) out.sign_key_type = KeyType::Ed25519;
            else if (oid_equal(sa_oid, OID_ED448, sizeof(OID_ED448))) out.sign_key_type = KeyType::Ed448;
            else if (oid_equal(sa_oid, OID_SM2_WITH_SM3, sizeof(OID_SM2_WITH_SM3))) out.sign_key_type = KeyType::SM2;
        }
    }
    auto sig_tlv = decode_tlv2(outer->value.data(), outer->value.size(), ooff);
    if (!sig_tlv || sig_tlv->tag != ASN1Tag::BIT_STRING) return std::nullopt;
    out.signature = tlv_to_bit_string(*sig_tlv);

    return out;
}
std::optional<csr> csr::from_der(const std::vector<uint8_t>& der) {
    return from_der(der.data(), der.size());
}
std::optional<csr> csr::from_pem(const std::string& pem) {
    auto der = pem_decode_block(pem, "CERTIFICATE REQUEST");
    if (!der) return std::nullopt;
    return from_der(*der);
}
std::optional<csr> csr::from_pem(const char* data, size_t len) {
    return from_pem(std::string(data, len));
}

} // namespace jpssl::x509
