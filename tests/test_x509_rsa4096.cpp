/**
 * test_x509_rsa4096.cpp — X.509 RSA-4096 证书 / 私钥 / CSR 解析与自签名生成
 *
 * 覆盖内容：
 *   1. RSA-4096 叶子证书解析：公钥类型识别为 KeyType::RSA_4096，公钥布局 n(512)||e(3)
 *   2. RSA-4096 叶子证书链验证：EC P-256 CA 签发的 RSA-4096 叶子（verify_signature）
 *   3. RSA-4096 PKCS#8 私钥解析：d 512 字节、CRT 参数 p/q/dP/dQ/qInv 各 256 字节
 *   4. RSA-4096 PKCS#10 CSR 解析：公钥 515 字节、签名 512 字节
 *   5. RSA-2048 回归：证书/私钥仍识别为 RSA_2048（公钥 259 字节）
 *   6. x509_builder::build_and_sign 自签名生成（RSA-4096 512 字节签名 / RSA-2048 回归）
 *
 * 测试证书：tests/certs/tls/（EC P-256 CA + RSA-2048/ECDSA leaf + RSA-4096 leaf/CSR）
 */

#include "x509.hpp"
#include "rsa.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>

using namespace jpssl;
using namespace jpssl::x509;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; } \
} while(0)

// ═══════════════════════════════════════════════════════════════════════
//  测试证书定位（ctest 工作目录可能是 build/tests，逐级向上查找源码树）
// ═══════════════════════════════════════════════════════════════════════
static std::string g_cert_dir;

static bool file_exists(const std::string& p) {
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return false;
    std::fclose(f);
    return true;
}

static std::string cert_dir() {
    if (!g_cert_dir.empty()) return g_cert_dir;
    static const char* candidates[] = {
        "tests/certs/tls", "../tests/certs/tls", "../../tests/certs/tls",
        "../../../tests/certs/tls", "certs/tls",
    };
    if (const char* env = std::getenv("JPSSL_TLS_CERT_DIR")) {
        if (file_exists(std::string(env) + "/server-rsa4096.pem")) {
            g_cert_dir = env;
            return g_cert_dir;
        }
    }
    for (const char* c : candidates) {
        if (file_exists(std::string(c) + "/server-rsa4096.pem")) {
            g_cert_dir = c;
            return g_cert_dir;
        }
    }
    g_cert_dir = "tests/certs/tls";  // 找不到时仍按默认路径尝试，便于报错定位
    return g_cert_dir;
}

static bool read_file(const std::string& path, std::string& out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz > 0) {
        out.resize((size_t)sz);
        size_t rd = std::fread(&out[0], 1, (size_t)sz, f);
        out.resize(rd);
    }
    std::fclose(f);
    return true;
}

static bool read_cert_file(const char* name, std::string& out) {
    return read_file(cert_dir() + "/" + name, out);
}

static const char* CN = "localhost";

static DistinguishedName make_cn(const char* cn) {
    DistinguishedName dn;
    dn.push_back({std::vector<uint8_t>(OID_CN, OID_CN + sizeof(OID_CN)), cn});
    return dn;
}

// ═══════════════════════════════════════════════════════════════════════
//  1. RSA-4096 证书解析
// ═══════════════════════════════════════════════════════════════════════
static void test_rsa4096_cert_parse() {
    std::printf("\n=== RSA-4096 证书解析 ===\n");
    std::string pem;
    TEST("读取 server-rsa4096.pem", read_cert_file("server-rsa4096.pem", pem));
    auto cert = x509_cert::from_pem(pem);
    TEST("RSA-4096 证书 PEM 解析", cert.has_value());
    if (!cert) return;

    TEST("公钥类型识别为 RSA_4096", cert->key_type == KeyType::RSA_4096);
    TEST("公钥布局 n(512)||e(3)", cert->public_key.size() == 515);
    TEST("CN = localhost", cert->common_name() == CN);
    TEST("issuer CN = jpssl TLS Test CA", cert->issuer_name() == "jpssl TLS Test CA");
    TEST("非 CA 证书", !cert->is_ca());
    TEST("有效期有效", cert->is_valid_now());
    auto sans = cert->dns_names();
    TEST("SAN 含 localhost", sans.size() == 1 && sans[0] == CN);

    // DER 往返（重新序列化后仍能解析且公钥一致）
    auto der = cert->to_der();
    auto again = x509_cert::from_der(der);
    TEST("DER 往返解析", again.has_value());
    if (again) {
        TEST("往返后公钥类型一致", again->key_type == KeyType::RSA_4096);
        TEST("往返后公钥一致", again->public_key == cert->public_key);
        TEST("往返后 CN 一致", again->common_name() == CN);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  2. RSA-4096 叶子 / EC CA 链验证
// ═══════════════════════════════════════════════════════════════════════
static void test_rsa4096_chain_verify() {
    std::printf("\n=== RSA-4096 叶子 + EC CA 链验证 ===\n");
    std::string leaf_pem, ca_pem;
    TEST("读取 server-rsa4096.pem", read_cert_file("server-rsa4096.pem", leaf_pem));
    TEST("读取 ca.pem", read_cert_file("ca.pem", ca_pem));
    auto leaf = x509_cert::from_pem(leaf_pem);
    auto ca = x509_cert::from_pem(ca_pem);
    TEST("CA 证书解析", ca.has_value());
    if (!leaf || !ca) return;
    TEST("CA 是 CA 证书", ca->is_ca());
    // 叶子签名由 EC P-256 CA 生成，验证依赖 CA 公钥（与叶子 RSA-4096 公钥无关）
    TEST("RSA-4096 叶子验签（EC CA）", leaf->verify_signature(*ca));
    TEST("链验证通过", x509_verify_chain({*leaf, *ca}).success);
    // 反向验证必须失败（公钥/私钥不匹配）
    TEST("错误 issuer 验签失败", !leaf->verify_signature(*leaf));
}

// ═══════════════════════════════════════════════════════════════════════
//  3. RSA-4096 私钥解析（PKCS#8）
// ═══════════════════════════════════════════════════════════════════════
static void test_rsa4096_private_key_parse() {
    std::printf("\n=== RSA-4096 私钥解析 ===\n");
    std::string pem;
    TEST("读取 server-rsa4096-key.pem", read_cert_file("server-rsa4096-key.pem", pem));
    auto key = private_key::from_pem(pem);
    TEST("RSA-4096 私钥 PEM 解析", key.has_value());
    if (!key) return;

    TEST("私钥类型 RSA_4096", key->key_type == KeyType::RSA_4096);
    TEST("d 为 512 字节", key->priv.size() == 512);
    TEST("公钥 n(512)||e(3)", key->pub.size() == 515);
    TEST("e = 65537", key->pub.size() >= 3 &&
                       key->pub[512] == 0x01 && key->pub[513] == 0x00 && key->pub[514] == 0x01);
    TEST("CRT p/q/dP/dQ/qInv 各 256 字节",
         key->rsa_p.size() == 256 && key->rsa_q.size() == 256 &&
         key->rsa_dP.size() == 256 && key->rsa_dQ.size() == 256 &&
         key->rsa_qInv.size() == 256);

    auto nonzero = [](const std::vector<uint8_t>& v) {
        for (uint8_t b : v) if (b != 0) return true;
        return false;
    };
    TEST("CRT 参数非零",
         nonzero(key->rsa_p) && nonzero(key->rsa_q) && nonzero(key->rsa_dP) &&
         nonzero(key->rsa_dQ) && nonzero(key->rsa_qInv));

    // 私钥公钥一致性：证书内公钥 == 私钥携带公钥
    std::string cert_pem;
    TEST("读取 server-rsa4096.pem", read_cert_file("server-rsa4096.pem", cert_pem));
    auto cert = x509_cert::from_pem(cert_pem);
    TEST("私钥公钥与证书公钥一致", cert && cert->public_key == key->pub);
}

// ═══════════════════════════════════════════════════════════════════════
//  4. RSA-4096 CSR 解析
// ═══════════════════════════════════════════════════════════════════════
static void test_rsa4096_csr_parse() {
    std::printf("\n=== RSA-4096 CSR 解析 ===\n");
    std::string pem;
    TEST("读取 server-rsa4096.csr", read_cert_file("server-rsa4096.csr", pem));
    auto req = csr::from_pem(pem);
    TEST("CSR PEM 解析", req.has_value());
    if (!req) return;
    TEST("CSR 公钥类型 RSA_4096", req->key_type == KeyType::RSA_4096);
    TEST("CSR 公钥 515 字节", req->public_key.size() == 515);
    TEST("CSR 签名 512 字节", req->signature.size() == 512);
    TEST("CSR subject CN = localhost", req->subject.size() == 1 &&
                                      req->subject[0].value == CN);
    TEST("CSR tbs 非空", !req->tbs_raw.empty());
}

// ═══════════════════════════════════════════════════════════════════════
//  5. RSA-2048 回归（证书仍识别为 RSA_2048）
// ═══════════════════════════════════════════════════════════════════════
static void test_rsa2048_regression() {
    std::printf("\n=== RSA-2048 回归 ===\n");
    std::string cert_pem, key_pem;
    TEST("读取 server-rsa.pem", read_cert_file("server-rsa.pem", cert_pem));
    TEST("读取 server-rsa-key.pem", read_cert_file("server-rsa-key.pem", key_pem));
    auto cert = x509_cert::from_pem(cert_pem);
    auto key = private_key::from_pem(key_pem);
    TEST("RSA-2048 证书解析", cert.has_value());
    TEST("RSA-2048 私钥解析", key.has_value());
    if (cert) {
        TEST("公钥类型仍为 RSA_2048", cert->key_type == KeyType::RSA_2048);
        TEST("公钥 n(256)||e(3)", cert->public_key.size() == 259);
    }
    if (key) {
        TEST("私钥类型仍为 RSA_2048", key->key_type == KeyType::RSA_2048);
        TEST("d 为 256 字节", key->priv.size() == 256);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  6. 自签名证书生成（RSA-4096 / RSA-2048）
// ═══════════════════════════════════════════════════════════════════════
static void test_build_and_sign(KeyType kt, size_t mod_bytes, const char* label) {
    std::string key_pem;
    char fname[64];
    std::snprintf(fname, sizeof(fname), "%s", kt == KeyType::RSA_4096
                                              ? "server-rsa4096-key.pem"
                                              : "server-rsa-key.pem");
    TEST((std::string("读取 ") + fname).c_str(), read_cert_file(fname, key_pem));
    auto key = private_key::from_pem(key_pem);
    TEST((std::string(label) + " 私钥解析").c_str(), key.has_value());
    if (!key) return;
    TEST((std::string(label) + " 私钥类型匹配").c_str(), key->key_type == kt);

    // 用私钥携带的公钥构造自签名证书
    x509_builder b;
    auto dn = make_cn(CN);
    b.set_subject(dn).set_issuer(dn);
    uint8_t serial[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    b.set_serial(serial, sizeof(serial));
    uint64_t now = (uint64_t)std::time(nullptr);
    b.set_validity(now - 60, now + 86400);
    b.set_key(kt, key->pub.data(), key->pub.size());
    b.set_ca(false).set_key_usage(KU_DIGITAL_SIGNATURE).set_server_auth().add_san_dns(CN);

    auto t0 = std::chrono::steady_clock::now();
    x509_cert self = b.build_and_sign(kt, key->priv.data(), key->priv.size());
    double ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
    std::printf("  [%s] build_and_sign: %.1f ms, 签名 %zu 字节\n",
                label, ms, self.signature.size());

    TEST((std::string(label) + " 签名长度 = 模数长度").c_str(),
         self.signature.size() == mod_bytes);
    TEST((std::string(label) + " 自签名验签通过").c_str(), self.verify_signature(self));
    TEST((std::string(label) + " 自签名有效期有效").c_str(), self.is_valid_now());
    TEST((std::string(label) + " 公钥类型正确").c_str(), self.key_type == kt);

    // DER 往返后仍可验签（TLS 自签名证书发送路径）
    auto der = self.to_der();
    auto parsed = x509_cert::from_der(der);
    TEST((std::string(label) + " DER 往返后可验签").c_str(),
         parsed && parsed->verify_signature(*parsed));
    if (parsed) {
        TEST((std::string(label) + " DER 往返后公钥类型").c_str(), parsed->key_type == kt);
        TEST((std::string(label) + " DER 往返后公钥一致").c_str(),
             parsed->public_key == self.public_key);
    }
}

int main() {
    std::printf("测试证书目录: %s\n", cert_dir().c_str());
    test_rsa4096_cert_parse();
    test_rsa4096_chain_verify();
    test_rsa4096_private_key_parse();
    test_rsa4096_csr_parse();
    test_rsa2048_regression();
    std::printf("\n=== 自签名证书生成 ===\n");
    test_build_and_sign(KeyType::RSA_2048, 256, "RSA-2048");
    test_build_and_sign(KeyType::RSA_4096, 512, "RSA-4096");

    std::printf("\n================================================\n");
    std::printf("  Result: %d passed, %d failed", pass, fail);
    std::printf(fail == 0 ? " ✓\n" : " ✗\n");
    std::printf("================================================\n");
    return fail > 0 ? 1 : 0;
}
