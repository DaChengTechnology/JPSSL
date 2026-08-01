/**
 * x509.cpp — X.509 v3 DER 编解码、证书生成与验证 (RFC 5280, 8410, 5758, GB/T 35275)
 * 完全自包含，不依赖 OpenSSL。
 */
#include "x509.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
    out.insert(out.end(), value, value + len);
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
    v.insert(v.end(), data, data + len);
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
        case KeyType::ECDSA_P256: case KeyType::SM2: {
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

    // version
    if (version > 0) {
        std::vector<uint8_t> v; v.push_back((uint8_t)(version - 1));
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

    // version [0]?
    if (first->tag == ASN1Tag::CONTEXT0) {
        size_t voff = 0;
        auto ver_tlv = decode_tlv2(first->value.data(), first->value.size(), voff);
        if (ver_tlv && ver_tlv->tag == ASN1Tag::INTEGER && !ver_tlv->value.empty())
            cert.version = (int)ver_tlv->value[0] + 1;
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
            }
        } else if (oid_equal(algo_oid, OID_ED25519, sizeof(OID_ED25519)))
            cert.key_type = KeyType::Ed25519;
        else if (oid_equal(algo_oid, OID_ED448, sizeof(OID_ED448)))
            cert.key_type = KeyType::Ed448;

        auto pub_tlv = decode_tlv2(spki_tlv->value.data(), spki_tlv->value.size(), soff);
        if (!pub_tlv || pub_tlv->tag != ASN1Tag::BIT_STRING) return std::nullopt;
        cert.public_key = tlv_to_bit_string(*pub_tlv);

        if ((cert.key_type == KeyType::ECDSA_P256 || cert.key_type == KeyType::SM2)
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
                    if (next && next->tag == ASN1Tag::BOOLEAN)
                        next = decode_tlv2(ext->value.data(), ext->value.size(), eioff);
                    if (!next || next->tag != ASN1Tag::OCTET_STRING) break;

                    if (oid_equal(eoid, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS))) {
                        size_t bioff = 0;
                        auto bc_seq = decode_tlv2(next->value.data(), next->value.size(), bioff);
                        if (bc_seq) {
                            BasicConstraints bc;
                            if (bioff < bc_seq->value.size()) {
                                auto ca_tlv = decode_tlv2(bc_seq->value.data(), bc_seq->value.size(), bioff);
                                if (ca_tlv && ca_tlv->tag == ASN1Tag::BOOLEAN)
                                    bc.ca = !ca_tlv->value.empty() && ca_tlv->value[0] != 0;
                            }
                            if (bioff < bc_seq->value.size()) {
                                auto pl_tlv = decode_tlv2(bc_seq->value.data(), bc_seq->value.size(), bioff);
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

} // namespace jpssl::x509
