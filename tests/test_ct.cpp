/**
 * test_ct.cpp -- SM2 Certificate Transparency (SM2 CT) unit tests
 *
 * Covers:
 *   1. base64 encode/decode (RFC 4648)
 *   2. SM3 Merkle tree: root, audit path, consistency proofs (RFC 6962 frame)
 *   3. SCT / STH serialization round-trips and SM2 signatures
 *   4. Full flow: SM2 CA -> precert -> log add-pre-chain -> SCT ->
 *      finalize_precert -> final cert SCT extraction -> add-chain -> STH
 */
#include "base64.hpp"
#include "ct.hpp"
#include "sm2.hpp"
#include "x509.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace jpssl;
using namespace jpssl::ct;
using namespace jpssl::x509;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; std::exit(1); } \
} while (0)

// RFC 6962 时钟：返回自 epoch 起的毫秒数（与 ct_log 默认时钟一致）。
// 证书有效期按秒计（RFC 5280），测试中需除以 1000。
static uint64_t fake_now() { return 1700000000000ULL; }

// ---------------------------------------------------------------------------
// 1. base64
// ---------------------------------------------------------------------------
static void test_base64() {
    std::printf("\n=== base64 ===\n");
    TEST("b64 known vector 'abc'", base64_encode((const uint8_t*)"abc", 3) == "YWJj");
    TEST("b64 known vector 'a'", base64_encode((const uint8_t*)"a", 1) == "YQ==");
    TEST("b64 known vector 'ab'", base64_encode((const uint8_t*)"ab", 2) == "YWI=");
    TEST("b64 empty", base64_encode((const uint8_t*)"", 0) == "");

    const uint8_t raw[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFE, 0xFF};
    std::vector<uint8_t> data(raw, raw + sizeof(raw));
    auto enc = base64_encode(data);
    auto dec = base64_decode(enc);
    TEST("b64 round-trip", dec.has_value() && *dec == data);
    auto dec2 = base64_decode("YWJj");
    std::vector<uint8_t> expect_abc = {'a', 'b', 'c'};
    TEST("b64 decode unpadded", dec2.has_value() && *dec2 == expect_abc);
    TEST("b64 reject bad char", !base64_decode("!!!!").has_value());
    TEST("b64 reject bad length", !base64_decode("YWI").has_value());
    TEST("b64 reject padding in middle", !base64_decode("YQ==YQ==").has_value());
}

// ---------------------------------------------------------------------------
// 2. SM3 Merkle tree
// ---------------------------------------------------------------------------
static void test_merkle_tree() {
    std::printf("\n=== SM3 Merkle tree ===\n");

    std::vector<node_hash> leaves;
    for (int i = 0; i < 7; ++i) {
        uint8_t b = (uint8_t)('a' + i);
        node_hash h;
        sm3_leaf_hash(&b, 1, h.data());
        leaves.push_back(h);
    }

    // Empty tree root == SM3(empty)
    {
        uint8_t expect[32];
        sm3_ctx ctx;
        sm3_init(&ctx);
        sm3_final(&ctx, expect);
        node_hash empty_expected{};
        memcpy(empty_expected.data(), expect, 32);
        TEST("empty tree root == SM3(empty)", merkle_root({}) == empty_expected);
    }

    // Audit paths verify for every (index, size)
    bool all_ok = true;
    for (size_t n = 1; n <= leaves.size(); ++n) {
        auto root = merkle_root(std::vector<node_hash>(leaves.begin(), leaves.begin() + n));
        for (size_t m = 0; m < n; ++m) {
            auto path = audit_path(m, std::vector<node_hash>(leaves.begin(), leaves.begin() + n));
            if (!verify_audit_path(m, n, leaves[m], path, root)) all_ok = false;
        }
    }
    TEST("audit paths verify (all n<=7)", all_ok);

    // Tampered path must fail
    {
        auto root = merkle_root(leaves);
        auto path = audit_path(3, leaves);
        if (!path.empty()) path[0] = node_hash{};
        TEST("tampered audit path rejected",
             !verify_audit_path(3, leaves.size(), leaves[3], path, root));
    }

    // Consistency proofs verify for every (first, second)
    bool all_cons = true;
    for (size_t second = 1; second <= leaves.size(); ++second) {
        auto root2 = merkle_root(std::vector<node_hash>(leaves.begin(), leaves.begin() + second));
        for (size_t first = 1; first <= second; ++first) {
            auto root1 = merkle_root(std::vector<node_hash>(leaves.begin(), leaves.begin() + first));
            auto proof = consistency_proof(first, second, leaves);
            if (!verify_consistency(first, second, root1, root2, proof)) all_cons = false;
        }
    }
    TEST("consistency proofs verify (all pairs)", all_cons);

    // first == second: empty proof
    {
        auto root = merkle_root(leaves);
        TEST("consistency first==second",
             verify_consistency(7, 7, root, root, {}));
        TEST("consistency first==second rejects nonempty",
             !verify_consistency(7, 7, root, root, {node_hash{}}));
    }
    TEST("consistency rejects first==0", !verify_consistency(0, 5, node_hash{}, node_hash{}, {}));
}

// ---------------------------------------------------------------------------
// 3. SCT / STH serialization
// ---------------------------------------------------------------------------
static void test_sct_sth() {
    std::printf("\n=== SCT / STH ===\n");

    uint8_t log_priv[SM2_KEY_SIZE], log_pub[SM2_PUB_SIZE];
    sm2_keygen(log_pub, log_priv);
    std::array<uint8_t, CT_LOG_ID_SIZE> log_id{};
    for (int i = 0; i < 32; ++i) log_id[i] = (uint8_t)i;

    std::vector<uint8_t> entry = {0x30, 0x03, 0x02, 0x01, 0x01};
    auto sct = issue_sct(log_priv, log_pub, log_id.data(), 123456789ULL,
                         LogEntryType::X509_ENTRY, entry, {1, 2, 3});
    auto ser = serialize_sct(sct);
    auto dec = deserialize_sct(ser.data(), ser.size());
    TEST("SCT round-trip", dec.has_value() && serialize_sct(*dec) == ser);
    TEST("SCT verify", verify_sct(sct, log_pub, LogEntryType::X509_ENTRY, entry));
    TEST("SCT verify wrong entry type",
         !verify_sct(sct, log_pub, LogEntryType::PRECERT_ENTRY, entry));
    uint8_t other_priv[SM2_KEY_SIZE], other_pub[SM2_PUB_SIZE];
    sm2_keygen(other_pub, other_priv);
    TEST("SCT verify wrong key",
         !verify_sct(sct, other_pub, LogEntryType::X509_ENTRY, entry));

    node_hash root{};
    root[0] = 0xAA;
    auto sth = sign_sth(log_priv, log_pub, 987654321ULL, 5, root);
    auto sth_ser = serialize_sth(sth);
    TEST("STH serialized size", sth_ser.size() == 1 + 8 + 8 + 32 + 1 + 1 + 2 + 64);
    TEST("STH verify", verify_sth(sth, log_pub));
    auto sth2 = sth;
    sth2.signature[0] ^= 0xFF;
    TEST("STH verify tampered sig", !verify_sth(sth2, log_pub));
}

// ---------------------------------------------------------------------------
// 4. Full SM2 CT flow
// ---------------------------------------------------------------------------
static x509_cert make_cert(const DistinguishedName& subject, const DistinguishedName& issuer,
                           const uint8_t* pub, size_t pub_len, bool ca,
                           uint64_t now, const uint8_t* ca_priv, size_t ca_priv_len,
                           const std::vector<RawExtension>& raw_exts = {}) {
    x509_builder b;
    b.set_subject(subject).set_issuer(issuer);
    uint8_t serial[8] = {0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    b.set_serial(serial, 8);
    b.set_validity(now - 86400, now + 3650 * 86400);
    b.set_key(KeyType::SM2, pub, pub_len);
    b.set_ca(ca, ca ? 0 : -1);
    b.set_key_usage(ca ? KU_KEY_CERT_SIGN : KU_DIGITAL_SIGNATURE);
    b.cert.raw_extensions = raw_exts;
    return b.build_and_sign(KeyType::SM2, ca_priv, ca_priv_len);
}

static bool has_extn(const std::vector<uint8_t>& cert_der, const uint8_t* oid, size_t oid_len) {
    auto cert = x509_cert::from_der(cert_der);
    if (!cert) return false;
    for (const auto& r : cert->raw_extensions)
        if (r.oid.size() == oid_len && memcmp(r.oid.data(), oid, oid_len) == 0) return true;
    return false;
}

static void test_full_flow() {
    std::printf("\n=== full SM2 CT flow ===\n");

    // Keys
    uint8_t ca_pub[SM2_PUB_SIZE], ca_priv[SM2_KEY_SIZE];
    sm2_keygen(ca_pub, ca_priv);
    uint8_t leaf_pub[SM2_PUB_SIZE], leaf_priv[SM2_KEY_SIZE];
    sm2_keygen(leaf_pub, leaf_priv);
    uint8_t log_pub[SM2_PUB_SIZE], log_priv[SM2_KEY_SIZE];
    sm2_keygen(log_pub, log_priv);

    uint64_t now = fake_now() / 1000;
    DistinguishedName root_dn;
    root_dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), "SM2 Root CA"});
    DistinguishedName leaf_dn;
    leaf_dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), "sm2ct.example.com"});

    // Root CA (self-signed)
    auto root_cert = make_cert(root_dn, root_dn, ca_pub, 64, true, now, ca_priv, 32);
    auto root_der = root_cert.to_der();
    TEST("root self-sig", root_cert.verify_signature(root_cert));

    // Precert: leaf subject, issuer root, poison extension, signed by CA
    std::vector<RawExtension> poison;
    poison.push_back(RawExtension{
        std::vector<uint8_t>(std::begin(OID_CT_POISON), std::end(OID_CT_POISON)),
        true, {0x05, 0x00}});  // extnValue = DER NULL
    auto precert = make_cert(leaf_dn, root_dn, leaf_pub, 64, false, now, ca_priv, 32, poison);
    auto precert_der = precert.to_der();
    TEST("precert has poison", has_extn(precert_der, OID_CT_POISON, sizeof(OID_CT_POISON)));
    TEST("precert signed by CA", precert.verify_signature(root_cert));

    // Log
    sm2_ct_log log(log_priv, log_pub, fake_now);
    log.accept_root(root_der);

    // add-pre-chain
    std::string err;
    auto sct = log.add_pre_chain({precert_der, root_der}, &err);
    TEST("add-pre-chain ok", sct.has_value());
    if (!sct) {
        std::printf("  error: %s\n", err.c_str());
        return;
    }

    // Rebuild the signed_entry the log used: issuer_key_hash + precert TBS
    auto root_c = x509_cert::from_der(root_der);
    TEST("issuer parse", root_c.has_value());
    auto precert_c = x509_cert::from_der(precert_der);
    TEST("precert parse", precert_c.has_value());
    pre_cert pc;
    {
        // Extract issuer SPKI raw bytes from the root certificate
        std::vector<uint8_t> spki;
        if (root_c) {
            size_t off = 0;
            auto c = der::decode_tlv(root_der.data(), root_der.size(), off);
            size_t io = 0;
            auto t = der::decode_tlv(c->value.data(), c->value.size(), io);
            std::vector<std::vector<uint8_t>> elems;
            size_t pos = 0;
            while (pos < t->value.size()) {
                size_t s = pos;
                auto el = der::decode_tlv(t->value.data(), t->value.size(), pos);
                if (!el) break;
                elems.emplace_back(t->value.begin() + s, t->value.begin() + pos);
            }
            size_t idx = (elems[0][0] & 0xE0) == 0xA0 ? 1 : 0;
            spki = elems[idx + 5];
        }
        sm3_hash(pc.issuer_key_hash.data(), spki.data(), spki.size());
        if (precert_c) pc.tbs_certificate = precert_c->tbs_raw;
    }
    auto signed_entry = make_precert_signed_entry(pc);
    TEST("SCT verify (precert)",
         verify_sct(*sct, log_pub, LogEntryType::PRECERT_ENTRY, signed_entry));

    // STH after 1 entry
    auto sth1 = log.get_sth();
    TEST("STH verify", verify_sth(sth1, log_pub));
    TEST("STH tree size 1", sth1.tree_size == 1);

    // Finalize precert -> final cert with SCT list
    auto final_cert = finalize_precert(precert, {*sct}, KeyType::SM2, ca_priv, 32);
    auto final_der = final_cert.to_der();
    TEST("final cert signed by CA", final_cert.verify_signature(root_cert));
    TEST("final cert has SCT list", has_extn(final_der, OID_SCT_LIST, sizeof(OID_SCT_LIST)));
    TEST("final cert has no poison", !has_extn(final_der, OID_CT_POISON, sizeof(OID_CT_POISON)));

    auto extracted = scts_from_cert(final_der);
    TEST("scts_from_cert ok", extracted.has_value() && extracted->size() == 1);
    if (extracted)
        TEST("extracted SCT matches", serialize_sct((*extracted)[0]) == serialize_sct(*sct));

    // precert_tbs_from_final: final TBS minus SCT list == precert TBS minus poison
    auto final_tbs = precert_tbs_from_final(final_der);
    TEST("precert_tbs_from_final ok", final_tbs.has_value());
    if (final_tbs) {
        // Wrap into a fake cert and confirm the SCT list extension is gone
        std::vector<uint8_t> fake_body;
        fake_body.insert(fake_body.end(), final_tbs->begin(), final_tbs->end());
        auto sig_algo = der::encode_sig_algo(KeyType::SM2);
        fake_body.insert(fake_body.end(), sig_algo.begin(), sig_algo.end());
        auto bs = der::encode_bit_string((const uint8_t*)"", 0, 0);
        fake_body.insert(fake_body.end(), bs.begin(), bs.end());
        auto fake_der = der::encode_sequence(fake_body);
        TEST("precert TBS has no SCT list",
             !has_extn(fake_der, OID_SCT_LIST, sizeof(OID_SCT_LIST)));
    }

    // add-chain for the final cert
    auto sct2 = log.add_chain({final_der, root_der}, &err);
    TEST("add-chain ok", sct2.has_value());
    if (!sct2) {
        std::printf("  error: %s\n", err.c_str());
        return;
    }
    TEST("SCT verify (final)",
         verify_sct(*sct2, log_pub, LogEntryType::X509_ENTRY, final_der));
    TEST("reject poisoned chain", !log.add_chain({precert_der, root_der}).has_value());
    TEST("reject unknown root", [&] {
        sm2_ct_log other(log_priv, log_pub, fake_now);  // no roots accepted
        return !other.add_chain({final_der, root_der}).has_value();
    }());

    // STH after 2 entries + consistency
    auto sth2 = log.get_sth();
    TEST("STH tree size 2", sth2.tree_size == 2);
    TEST("STH2 verify", verify_sth(sth2, log_pub));
    auto proof = log.get_sth_consistency(1, 2);
    TEST("consistency 1->2",
         verify_consistency(1, 2, sth1.root_hash, sth2.root_hash, proof));

    // Proof by hash + audit path
    uint64_t idx = 0;
    std::vector<node_hash> path;
    TEST("proof-by-hash", log.get_proof_by_hash(log.leaf_hash_at(0), 2, &idx, &path));
    TEST("proof-by-hash index", idx == 0);
    TEST("audit path verifies",
         verify_audit_path((size_t)idx, 2, log.leaf_hash_at(0), path, sth2.root_hash));

    // get-entries
    std::vector<std::vector<uint8_t>> leaf_inputs, extra_datas;
    TEST("get-entries ok", log.get_entries(0, 1, &leaf_inputs, &extra_datas));
    TEST("get-entries count", leaf_inputs.size() == 2 && extra_datas.size() == 2);
    {
        auto l0 = deserialize_merkle_tree_leaf(leaf_inputs[0].data(), leaf_inputs[0].size());
        TEST("entry0 is precert", l0.has_value() &&
                                  l0->entry_type == LogEntryType::PRECERT_ENTRY &&
                                  l0->signed_entry == signed_entry);
        auto l1 = deserialize_merkle_tree_leaf(leaf_inputs[1].data(), leaf_inputs[1].size());
        TEST("entry1 is x509", l1.has_value() &&
                               l1->entry_type == LogEntryType::X509_ENTRY &&
                               l1->signed_entry == final_der);
    }

    // base64 of a certificate (as used by the JSON HTTP API)
    auto b64 = base64_encode(final_der);
    auto back = base64_decode(b64);
    TEST("cert base64 round-trip", back.has_value() && *back == final_der);
}

// ---------------------------------------------------------------------------
// 5. Standard (RFC 6962) CT flow: SHA-256 + ECDSA P-256
// ---------------------------------------------------------------------------
static void test_std_flow() {
    std::printf("\n=== standard (RFC 6962) CT flow ===\n");

    // ---- SHA-256 Merkle tree: root / audit / consistency (all pairs) ----
    std::vector<node_hash> leaves;
    for (int i = 0; i < 7; ++i) {
        uint8_t b = (uint8_t)('a' + i);
        node_hash h;
        sha256_leaf_hash(&b, 1, h.data());
        leaves.push_back(h);
    }
    {
        uint8_t expect[32];
        sha256(nullptr, 0, expect);
        node_hash empty_expected{};
        memcpy(empty_expected.data(), expect, 32);
        TEST("sha256 empty root == SHA-256(empty)",
             merkle_root({}, CtHashAlg::SHA256) == empty_expected);
    }
    bool all_audit = true;
    for (size_t n = 1; n <= leaves.size(); ++n) {
        auto root = merkle_root(std::vector<node_hash>(leaves.begin(), leaves.begin() + n),
                                CtHashAlg::SHA256);
        for (size_t m = 0; m < n; ++m) {
            auto path = audit_path(m, std::vector<node_hash>(leaves.begin(), leaves.begin() + n),
                                   CtHashAlg::SHA256);
            if (!verify_audit_path(m, n, leaves[m], path, root, CtHashAlg::SHA256))
                all_audit = false;
        }
    }
    TEST("sha256 audit paths verify (all n<=7)", all_audit);

    bool all_cons = true;
    for (size_t second = 1; second <= leaves.size(); ++second) {
        auto root2 = merkle_root(std::vector<node_hash>(leaves.begin(), leaves.begin() + second),
                                 CtHashAlg::SHA256);
        for (size_t first = 1; first <= second; ++first) {
            auto root1 = merkle_root(std::vector<node_hash>(leaves.begin(), leaves.begin() + first),
                                     CtHashAlg::SHA256);
            auto proof = consistency_proof(first, second, leaves, CtHashAlg::SHA256);
            if (!verify_consistency(first, second, root1, root2, proof, CtHashAlg::SHA256))
                all_cons = false;
        }
    }
    TEST("sha256 consistency proofs verify (all pairs)", all_cons);

    // ---- Standard SCT / STH (SHA-256 + ECDSA P-256) ----
    uint8_t log_priv[32], log_pub[64];
    ecdsa_p256_keygen(log_pub, log_priv);
    std::array<uint8_t, CT_LOG_ID_SIZE> log_id{};
    for (int i = 0; i < 32; ++i) log_id[i] = (uint8_t)i;

    std::vector<uint8_t> entry = {0x30, 0x03, 0x02, 0x01, 0x01};
    auto sct = issue_sct_std(log_priv, log_pub, log_id.data(), 123456789ULL,
                             LogEntryType::X509_ENTRY, entry, {1, 2, 3});
    TEST("std SCT algorithms", sct.hash_algorithm == CT_HASH_ALG_SHA256 &&
                               sct.signature_algorithm == CT_SIG_ALG_ECDSA);
    auto ser = serialize_sct(sct);
    auto dec = deserialize_sct(ser.data(), ser.size());
    TEST("std SCT round-trip", dec.has_value() && serialize_sct(*dec) == ser);
    TEST("std SCT verify", verify_sct_std(sct, log_pub, LogEntryType::X509_ENTRY, entry));
    TEST("std SCT wrong entry type",
         !verify_sct_std(sct, log_pub, LogEntryType::PRECERT_ENTRY, entry));
    uint8_t other_pub[64];
    uint8_t other_priv[32];
    ecdsa_p256_keygen(other_pub, other_priv);
    TEST("std SCT wrong key",
         !verify_sct_std(sct, other_pub, LogEntryType::X509_ENTRY, entry));

    node_hash root{};
    root[0] = 0xAA;
    auto sth = sign_sth_std(log_priv, log_pub, 987654321ULL, 5, root);
    TEST("std STH verify", verify_sth_std(sth, log_pub));
    auto sth2 = sth;
    sth2.signature[0] ^= 0xFF;
    TEST("std STH tampered sig", !verify_sth_std(sth2, log_pub));

    // ---- Full standard flow: ECDSA CA -> precert -> log -> final cert ----
    uint8_t ca_pub[64], ca_priv[32];
    ecdsa_p256_keygen(ca_pub, ca_priv);
    uint8_t leaf_pub[64], leaf_priv[32];
    ecdsa_p256_keygen(leaf_pub, leaf_priv);

    uint64_t now = fake_now() / 1000;
    DistinguishedName root_dn;
    root_dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), "ECDSA Root CA"});
    DistinguishedName leaf_dn;
    leaf_dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), "ct.example.com"});

    auto make_ec_cert = [&](const DistinguishedName& subject, const DistinguishedName& issuer,
                            const uint8_t* pub, bool is_ca, const uint8_t* sign_priv,
                            const std::vector<RawExtension>& raw_exts = {}) {
        x509_builder b;
        b.set_subject(subject).set_issuer(issuer);
        uint8_t serial[8] = {0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        b.set_serial(serial, 8);
        b.set_validity(now - 86400, now + 3650 * 86400);
        b.set_key(KeyType::ECDSA_P256, pub, 64);
        b.set_ca(is_ca, is_ca ? 0 : -1);
        b.set_key_usage(is_ca ? KU_KEY_CERT_SIGN : KU_DIGITAL_SIGNATURE);
        b.cert.raw_extensions = raw_exts;
        return b.build_and_sign(KeyType::ECDSA_P256, sign_priv, 32);
    };

    auto root_cert = make_ec_cert(root_dn, root_dn, ca_pub, true, ca_priv);
    auto root_der = root_cert.to_der();
    TEST("std root self-sig", root_cert.verify_signature(root_cert));

    std::vector<RawExtension> poison;
    poison.push_back(RawExtension{
        std::vector<uint8_t>(std::begin(OID_CT_POISON), std::end(OID_CT_POISON)),
        true, {0x05, 0x00}});
    auto precert = make_ec_cert(leaf_dn, root_dn, leaf_pub, false, ca_priv, poison);
    auto precert_der = precert.to_der();
    TEST("std precert signed by CA", precert.verify_signature(root_cert));

    ct_log log(CtHashAlg::SHA256, CtSigAlg::ECDSA_P256, log_priv, log_pub, fake_now);
    log.accept_root(root_der);
    std::string err;
    auto sct1 = log.add_pre_chain({precert_der, root_der}, &err);
    TEST("std add-pre-chain ok", sct1.has_value());
    if (!sct1) {
        std::printf("  error: %s\n", err.c_str());
        return;
    }

    // Rebuild the precert signed_entry: issuer_key_hash = SHA-256(issuer SPKI)
    auto root_c = x509_cert::from_der(root_der);
    auto precert_c = x509_cert::from_der(precert_der);
    pre_cert pc;
    if (root_c && precert_c) {
        size_t off = 0;
        auto c = der::decode_tlv(root_der.data(), root_der.size(), off);
        size_t io = 0;
        auto t = der::decode_tlv(c->value.data(), c->value.size(), io);
        std::vector<std::vector<uint8_t>> elems;
        size_t pos = 0;
        while (pos < t->value.size()) {
            size_t s = pos;
            auto el = der::decode_tlv(t->value.data(), t->value.size(), pos);
            if (!el) break;
            elems.emplace_back(t->value.begin() + s, t->value.begin() + pos);
        }
        size_t idx = (elems[0][0] & 0xE0) == 0xA0 ? 1 : 0;
        auto& spki = elems[idx + 5];
        sha256(spki.data(), spki.size(), pc.issuer_key_hash.data());
        pc.tbs_certificate = precert_c->tbs_raw;
    }
    auto signed_entry = make_precert_signed_entry(pc);
    TEST("std SCT verify (precert)",
         verify_sct_std(*sct1, log_pub, LogEntryType::PRECERT_ENTRY, signed_entry));
    {
        auto spki = der::encode_spki(KeyType::ECDSA_P256, log_pub, 64);
        node_hash expect{};
        sha256(spki.data(), spki.size(), expect.data());
        TEST("std log_id == SHA-256(SPKI)", log.log_id() == expect);
    }

    auto sth1 = log.get_sth();
    TEST("std STH verify", verify_sth_std(sth1, log_pub));
    TEST("std STH tree size 1", sth1.tree_size == 1);

    auto final_cert = finalize_precert(precert, {*sct1}, KeyType::ECDSA_P256, ca_priv, 32);
    auto final_der = final_cert.to_der();
    TEST("std final cert signed by CA", final_cert.verify_signature(root_cert));
    TEST("std final cert has SCT list",
         has_extn(final_der, OID_SCT_LIST, sizeof(OID_SCT_LIST)));
    TEST("std final cert has no poison",
         !has_extn(final_der, OID_CT_POISON, sizeof(OID_CT_POISON)));
    auto extracted = scts_from_cert(final_der);
    TEST("std scts_from_cert ok", extracted.has_value() && extracted->size() == 1);
    if (extracted)
        TEST("std extracted SCT matches", serialize_sct((*extracted)[0]) == serialize_sct(*sct1));

    auto sct2 = log.add_chain({final_der, root_der}, &err);
    TEST("std add-chain ok", sct2.has_value());
    if (sct2)
        TEST("std SCT verify (final)",
             verify_sct_std(*sct2, log_pub, LogEntryType::X509_ENTRY, final_der));

    auto sth2b = log.get_sth();
    TEST("std STH tree size 2", sth2b.tree_size == 2);
    auto proof = log.get_sth_consistency(1, 2);
    TEST("std consistency 1->2",
         verify_consistency(1, 2, sth1.root_hash, sth2b.root_hash, proof, CtHashAlg::SHA256));

    uint64_t idx = 0;
    std::vector<node_hash> path;
    TEST("std proof-by-hash",
         log.get_proof_by_hash(log.leaf_hash_at(0), 2, &idx, &path));
    TEST("std audit path verifies",
         verify_audit_path((size_t)idx, 2, log.leaf_hash_at(0), path, sth2b.root_hash,
                           CtHashAlg::SHA256));

    // LogID from the log certificate (X.509 integration)
    x509_builder lb;
    DistinguishedName log_dn;
    log_dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), "CT Log"});
    lb.set_subject(log_dn).set_issuer(log_dn);
    uint8_t serial[8] = {0x77, 0, 0, 0, 0, 0, 0, 0};
    lb.set_serial(serial, 8);
    lb.set_validity(now - 86400, now + 3650 * 86400);
    lb.set_key(KeyType::ECDSA_P256, log_pub, 64);
    lb.set_ca(false);
    auto log_cert = lb.build_and_sign(KeyType::ECDSA_P256, log_priv, 32);
    TEST("compute_log_id_std == log.log_id()",
         compute_log_id_std(log_cert) == log.log_id());
}

// ---------------------------------------------------------------------------
// 6. RFC 6962 RSA CT：SHA-256 + RSA-2048 PKCS#1 v1.5
// ---------------------------------------------------------------------------
static void test_rsa_flow() {
    std::printf("\n=== RFC 6962 RSA CT flow ===\n");

    rsa_public_key log_pub;
    rsa_crt_key log_priv;
    TEST("rsa keygen", rsa_keygen_crt(log_pub, log_priv));

    std::array<uint8_t, CT_LOG_ID_SIZE> log_id{};
    {
        uint8_t p[259];
        log_pub.n.to_bytes(p);
        p[256] = 1; p[257] = 0; p[258] = 1;
        auto spki = der::encode_spki(KeyType::RSA_2048, p, 259);
        sha256(spki.data(), spki.size(), log_id.data());
    }

    std::vector<uint8_t> entry = {0x30, 0x03, 0x02, 0x01, 0x01};
    auto sct = issue_sct_rsa(log_priv, log_id.data(), 123456789ULL,
                             LogEntryType::X509_ENTRY, entry, {});
    TEST("rsa SCT algorithms", sct.hash_algorithm == CT_HASH_ALG_SHA256 &&
                               sct.signature_algorithm == CT_SIG_ALG_RSA);
    TEST("rsa SCT signature size", sct.signature.size() == 256);
    auto ser = serialize_sct(sct);
    auto dec = deserialize_sct(ser.data(), ser.size());
    TEST("rsa SCT round-trip", dec.has_value() && serialize_sct(*dec) == ser);
    TEST("rsa SCT verify", verify_sct_rsa(sct, log_pub, LogEntryType::X509_ENTRY, entry));
    TEST("rsa SCT wrong entry type",
         !verify_sct_rsa(sct, log_pub, LogEntryType::PRECERT_ENTRY, entry));
    rsa_public_key other_pub;
    rsa_crt_key other_priv;
    rsa_keygen_crt(other_pub, other_priv);
    TEST("rsa SCT wrong key",
         !verify_sct_rsa(sct, other_pub, LogEntryType::X509_ENTRY, entry));

    node_hash root{};
    root[0] = 0xAA;
    auto sth = sign_sth_rsa(log_priv, 987654321ULL, 5, root);
    TEST("rsa STH verify", verify_sth_rsa(sth, log_pub));
    auto sth2 = sth;
    sth2.signature[0] ^= 0xFF;
    TEST("rsa STH tampered sig", !verify_sth_rsa(sth2, log_pub));

    // RSA 日志：get_sth 用 RSA 签名，且 log_id == SHA-256(SPKI)
    ct_log rlog(log_priv, log_pub, fake_now);
    TEST("rsa log log_id", rlog.log_id() == log_id);
    auto sth3 = rlog.get_sth();
    TEST("rsa log STH verify", verify_sth_rsa(sth3, log_pub));
    TEST("rsa log STH tree size 0", sth3.tree_size == 0);
}

int main() {
    test_base64();
    test_merkle_tree();
    test_sct_sth();
    test_full_flow();
    test_std_flow();
    test_rsa_flow();
    std::printf("\n%d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
