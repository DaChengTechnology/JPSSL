/**
 * jpssl-cert — X.509 v3 证书生成/查看/验证命令行工具
 *
 * 用法:
 *   jpssl-cert gen    --cn <name> [--key-type ed25519|ecdsa|sm2|rsa2048] [--days 365]
 *                     [--out cert.der] [--key-out key.bin]
 *   jpssl-cert info   --cert <file.der>
 *   jpssl-cert verify --cert <leaf.der> --ca <root.der>
 *   jpssl-cert chain  --cert <leaf.der> --ca <root.der> [--ca <inter.der> ...]
 *   jpssl-cert tlsgen --cn <name> [--key-type ed25519|ecdsa|sm2|rsa2048] [--days 365]
 *                     [--out cert.der] [--key-out key.bin]
 */

#include "x509.hpp"
#include "tls.hpp"
#include "ed25519.hpp"
#include "ed448.hpp"
#include "ecdsa.hpp"
#include "sm2.hpp"
#include "rsa.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

using namespace jpssl;
using namespace jpssl::x509;
using namespace jpssl::tls;

// ── helpers ────────────────────────────────────────────────────────────────
static void die(const char* msg) { std::fprintf(stderr, "ERROR: %s\n", msg); std::exit(1); }
static void check_days(int days) {
    if (days < 1) die("有效期天数无效: --days 必须 >= 1");
}
static void usage() {
    std::printf(R"(jpssl-cert — X.509 v3 证书工具

用法:
  jpssl-cert gen    --cn <name> [--key-type ed25519|ecdsa|sm2|rsa2048] [--days 365]
                    [--out cert.der] [--key-out key.bin]
  jpssl-cert info   --cert <file.der>
  jpssl-cert verify --cert <leaf.der> --ca <root.der> [--ca <inter.der> ...]
  jpssl-cert chain  --cert <leaf.der> --ca <root.der> [--ca <inter.der> ...]
  jpssl-cert tlsgen --cn <name> [--key-type ed25519|ecdsa|sm2|rsa2048]
                    [--days 365] [--out cert.der] [--key-out key.bin]

选项:
  --cn, --common-name <name>    Subject Common Name
  --key-type <type>             密钥类型 (默认 ed25519)
  --days <n>                    有效期天数 (默认 365, gen/tlsgen 均支持)
  --out, --cert <file>          输出/输入 证书文件 (DER)
  --key-out <file>              私钥输出文件
  --ca <file>                   CA 证书文件 (可多次指定)
)");
}

static std::vector<uint8_t> read_file(const char* path) {
    FILE* f = std::fopen(path, "rb");
    if (!f) die("无法打开文件");
    std::fseek(f, 0, SEEK_END);
    size_t sz = (size_t)std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> data(sz);
    if (sz > 0) std::fread(data.data(), 1, sz, f);
    std::fclose(f);
    return data;
}

static void write_file(const char* path, const std::vector<uint8_t>& data) {
    FILE* f = std::fopen(path, "wb");
    if (!f) die("无法创建文件");
    if (!data.empty()) std::fwrite(data.data(), 1, data.size(), f);
    std::fclose(f);
}

static void hex_dump(const uint8_t* d, size_t n) {
    for (size_t i = 0; i < n; ++i) std::printf("%02x", d[i]);
    std::printf("\n");
}

// ── key I/O ────────────────────────────────────────────────────────────────
struct KeyPair {
    KeyType kt;
    std::vector<uint8_t> pub;
    std::vector<uint8_t> priv;
};

static KeyPair gen_keypair(const std::string& type) {
    KeyPair kp;
    if (type == "ed25519") {
        kp.kt = KeyType::Ed25519;
        kp.pub.resize(32); kp.priv.resize(64);
        ed25519_keygen(kp.pub.data(), kp.priv.data());
    } else if (type == "ecdsa") {
        kp.kt = KeyType::ECDSA_P256;
        kp.pub.resize(64); kp.priv.resize(32);
        ecdsa_p256_keygen(kp.pub.data(), kp.priv.data());
    } else if (type == "sm2") {
        kp.kt = KeyType::SM2;
        kp.pub.resize(64); kp.priv.resize(32);
        sm2_keygen(kp.pub.data(), kp.priv.data());
    } else if (type == "rsa2048") {
        kp.kt = KeyType::RSA_2048;
        rsa_public_key pub; rsa_private_key prv;
        if (!rsa_keygen(pub, prv)) die("RSA 密钥生成失败");
        kp.pub.resize(259);
        pub.n.to_bytes(kp.pub.data());
        kp.pub[256] = 0x01; kp.pub[257] = 0x00; kp.pub[258] = 0x01;
        kp.priv.resize(256);
        prv.d.to_bytes(kp.priv.data());
    } else if (type == "ed448") {
        kp.kt = KeyType::Ed448;
        kp.pub.resize(57); kp.priv.resize(57);
        ed448_keygen(kp.pub.data(), kp.priv.data());
    } else {
        die("未知密钥类型，支持: ed25519, ecdsa, sm2, rsa2048, ed448");
    }
    return kp;
}

// ── subcommands ────────────────────────────────────────────────────────────

static void cmd_gen(int argc, char** argv) {
    std::string cn = "localhost", key_type = "ed25519";
    int days = 365;
    const char* out_file = "cert.der";
    const char* key_file = "key.bin";

    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--cn") || !std::strcmp(argv[i], "--common-name"))
            { if (++i < argc) cn = argv[i]; }
        else if (!std::strcmp(argv[i], "--key-type"))
            { if (++i < argc) key_type = argv[i]; }
        else if (!std::strcmp(argv[i], "--days"))
            { if (++i < argc) days = std::atoi(argv[i]); }
        else if (!std::strcmp(argv[i], "--out"))
            { if (++i < argc) out_file = argv[i]; }
        else if (!std::strcmp(argv[i], "--key-out"))
            { if (++i < argc) key_file = argv[i]; }
    }
    check_days(days);

    auto kp = gen_keypair(key_type);
    std::printf("生成 %s 密钥对...\n", key_type.c_str());

    x509_builder b;
    DistinguishedName dn;
    dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), cn});
    b.set_subject(dn).set_issuer(dn);

    uint8_t serial[8] = {1};
    b.set_serial(serial, 8);

    uint64_t now = (uint64_t)std::time(nullptr);
    b.set_validity(now, now + (uint64_t)days * 86400);

    b.set_key(kp.kt, kp.pub.data(), kp.pub.size());
    b.set_ca(false);
    b.set_key_usage(KU_DIGITAL_SIGNATURE);
    b.set_server_auth();
    b.add_san_dns(cn);

    auto cert = b.build_and_sign(kp.kt, kp.priv.data(), kp.priv.size());
    auto der = cert.to_der();

    write_file(out_file, der);
    write_file(key_file, kp.priv);
    std::printf("证书: %s (%zu bytes)\n私钥: %s (%zu bytes)\nCN: %s\n有效期: %d 天\n",
                out_file, der.size(), key_file, kp.priv.size(), cn.c_str(), days);
}

static void cmd_info(int argc, char** argv) {
    const char* cert_file = nullptr;
    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--cert"))
            { if (++i < argc) cert_file = argv[i]; }
    }
    if (!cert_file) die("需要 --cert <file>");

    auto der = read_file(cert_file);
    auto cert = x509_cert::from_der(der);
    if (!cert) die("无法解析证书 (无效 DER)");

    const char* kt_names[] = {"RSA-2048","RSA-4096","Ed25519","Ed448","ECDSA-P256","SM2"};
    std::printf("Subject CN : %s\n", cert->common_name().c_str());
    std::printf("Issuer  CN : %s\n", cert->issuer_name().c_str());
    std::printf("Key type   : %s\n", kt_names[(int)cert->key_type]);
    std::printf("Is CA      : %s\n", cert->is_ca() ? "yes" : "no");
    std::printf("Valid now  : %s\n", cert->is_valid_now() ? "yes" : "no");
    std::printf("Serial     : "); hex_dump(cert->serial_number.data(), cert->serial_number.size());
    auto dns = cert->dns_names();
    if (!dns.empty()) {
        std::printf("SAN DNS    :");
        for (auto& d : dns) std::printf(" %s", d.c_str());
        std::printf("\n");
    }
    std::printf("Sig size   : %zu bytes\n", cert->signature.size());
    std::printf("DER size   : %zu bytes\n", der.size());
}

static void cmd_verify(int argc, char** argv) {
    const char* cert_file = nullptr;
    std::vector<const char*> ca_files;
    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--cert"))
            { if (++i < argc) cert_file = argv[i]; }
        else if (!std::strcmp(argv[i], "--ca"))
            { if (++i < argc) ca_files.push_back(argv[i]); }
    }
    if (!cert_file) die("需要 --cert <file>");
    if (ca_files.empty()) die("需要至少一个 --ca <file>");

    auto leaf_der = read_file(cert_file);
    auto leaf = x509_cert::from_der(leaf_der);
    if (!leaf) die("无法解析叶子证书");

    std::vector<x509_cert> chain;
    chain.push_back(*leaf);
    for (auto f : ca_files) {
        auto ca_der = read_file(f);
        auto ca = x509_cert::from_der(ca_der);
        if (!ca) die("无法解析 CA 证书");
        chain.push_back(*ca);
    }

    auto result = x509_verify_chain(chain);
    if (result.success) {
        std::printf("✓ 证书链验证通过 (%zu 张证书)\n", chain.size());
    } else {
        std::printf("✗ 证书链验证失败: %s\n", result.error.c_str());
        std::exit(1);
    }
}

static void cmd_tlsgen(int argc, char** argv) {
    std::string cn = "localhost", key_type = "ed25519";
    int days = 365;
    const char* out_file = "cert.der";
    const char* key_file = "key.bin";

    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--cn") || !std::strcmp(argv[i], "--common-name"))
            { if (++i < argc) cn = argv[i]; }
        else if (!std::strcmp(argv[i], "--key-type"))
            { if (++i < argc) key_type = argv[i]; }
        else if (!std::strcmp(argv[i], "--days"))
            { if (++i < argc) days = std::atoi(argv[i]); }
        else if (!std::strcmp(argv[i], "--out"))
            { if (++i < argc) out_file = argv[i]; }
        else if (!std::strcmp(argv[i], "--key-out"))
            { if (++i < argc) key_file = argv[i]; }
    }
    check_days(days);

    auto tls_cert = std::make_unique<tls_certificate>();
    tls_cert->subject_name = cn;

    if (key_type == "ed25519") {
        tls_cert->sig_alg = SignatureAlgorithm::ED25519;
        ed25519_keygen(tls_cert->pub.ed25519, tls_cert->priv.ed25519);
    } else if (key_type == "ecdsa") {
        tls_cert->sig_alg = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
        ecdsa_p256_keygen(tls_cert->pub.ecdsa_p256, tls_cert->priv.ecdsa_p256);
    } else if (key_type == "sm2") {
        tls_cert->sig_alg = SignatureAlgorithm::SM2_SM3;
        sm2_keygen(tls_cert->pub.sm2, tls_cert->priv.sm2);
    } else if (key_type == "rsa2048") {
        tls_cert->sig_alg = SignatureAlgorithm::RSA_PKCS1_SHA256;
        rsa_keygen(tls_cert->pub.rsa, tls_cert->priv.rsa);
    } else if (key_type == "ed448") {
        tls_cert->sig_alg = SignatureAlgorithm::ED448;
        ed448_keygen(tls_cert->pub.ed448, tls_cert->priv.ed448);
    } else {
        die("未知密钥类型");
    }

    auto der = tls_make_x509_self_signed(*tls_cert, days);
    write_file(out_file, der);

    // Write private key
    std::vector<uint8_t> priv_data;
    if (key_type == "ed25519")
        priv_data.assign(tls_cert->priv.ed25519, tls_cert->priv.ed25519 + 64);
    else if (key_type == "ecdsa")
        priv_data.assign(tls_cert->priv.ecdsa_p256, tls_cert->priv.ecdsa_p256 + 32);
    else if (key_type == "sm2")
        priv_data.assign(tls_cert->priv.sm2, tls_cert->priv.sm2 + 32);
    else if (key_type == "ed448")
        priv_data.assign(tls_cert->priv.ed448, tls_cert->priv.ed448 + 57);
    else if (key_type == "rsa2048") {
        priv_data.resize(256);
        tls_cert->priv.rsa.d.to_bytes(priv_data.data());
    }
    write_file(key_file, priv_data);

    std::printf("TLS 证书 (X.509 v3): %s (%zu bytes)\n私钥: %s (%zu bytes)\nCN: %s\n有效期: %d 天\n",
                out_file, der.size(), key_file, priv_data.size(), cn.c_str(), days);
}

// ── main ───────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    const char* cmd = argv[1];

    if (!std::strcmp(cmd, "gen"))       cmd_gen(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "info")) cmd_info(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "verify")) cmd_verify(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "chain")) cmd_verify(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "tlsgen")) cmd_tlsgen(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "-h") || !std::strcmp(cmd, "--help")) usage();
    else { std::fprintf(stderr, "未知命令: %s\n", cmd); usage(); return 1; }
    return 0;
}
