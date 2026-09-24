/**
 * test_cmd_cert_rsa4096.cpp — jpssl-cert CLI 的 RSA-4096 密钥类型端到端测试
 *
 * 覆盖内容：
 *   1. tlsgen --key-type rsa4096：生成 TLS 自签名证书 + PKCS#8 私钥，退出码 0
 *   2. gen    --key-type rsa4096：生成通用自签名证书 + PKCS#8 私钥，退出码 0
 *   3. info   --cert：识别证书公钥为 RSA-4096
 *   4. key    --key：识别私钥为 RSA-4096（私钥 512 字节 / 公钥 515 字节）
 *   5. 私钥 API 校验：private_key::from_pem → RSA_4096，d=512、n||e=515、
 *      CRT 参数 p/q/dP/dQ/qInv 各 256 字节且非零
 *   6. 证书 API 校验：x509_cert::from_der → RSA_4096、公钥 515 字节、
 *      有效期覆盖当前时间、自签名 verify_signature 通过
 *   7. 服务端装载链路：tls_certificate::from_pem(cert_pem, key_pem) → rsa4096=true，
 *      RSA-PSS-RSAE-SHA256 签名 512 字节、验签通过、篡改 1 字节后验签失败
 *
 * 用法: test_cmd_cert_rsa4096 <jpssl-cert 可执行文件路径>
 *       未提供路径时打印 SKIP 并返回 0（便于在未构建 CLI 的环境下跳过）。
 */

#include "x509.hpp"
#include "tls.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>

using namespace jpssl;
using namespace jpssl::x509;
using namespace jpssl::tls;
namespace fs = std::filesystem;

static int pass = 0, fail = 0;

#define TEST(name, cond) do { \
    if (cond) { std::printf("  PASS: %s\n", name); pass++; } \
    else { std::fprintf(stderr, "  FAIL: %s\n", name); fail++; } \
} while(0)

// ── 文件 / 进程辅助 ────────────────────────────────────────────────────────

static bool read_file_bytes(const fs::path& p, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(p.string().c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz < 0) { std::fclose(f); return false; }
    out.assign((size_t)sz, 0);
    size_t rd = sz > 0 ? std::fread(out.data(), 1, (size_t)sz, f) : 0;
    out.resize(rd);
    std::fclose(f);
    return true;
}

static bool read_file_text(const fs::path& p, std::string& out) {
    std::vector<uint8_t> b;
    if (!read_file_bytes(p, b)) return false;
    out.assign(b.begin(), b.end());
    return true;
}

/// 执行命令并把 stdout+stderr 收集到 out（经临时文件重定向，避免管道缓冲问题）。
/// 返回退出码；0 表示成功。
static int run_cmd(const std::string& cmd, const fs::path& log_file, std::string& out) {
    std::string full = cmd + " > \"" + log_file.string() + "\" 2>&1";
    int rc = std::system(full.c_str());
    out.clear();
    read_file_text(log_file, out);
    return rc;
}

/// 统计向量中非零字节数（用于校验 CRT 参数确实被填充）
static size_t nonzero_bytes(const std::vector<uint8_t>& v) {
    size_t n = 0;
    for (uint8_t b : v) if (b != 0) n++;
    return n;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("SKIP: 未提供 jpssl-cert 可执行文件路径（用法: %s <jpssl-cert>）\n", argv[0]);
        return 0;
    }
    const std::string cli = argv[1];
    if (!fs::exists(cli)) {
        std::fprintf(stderr, "FAIL: jpssl-cert 不存在: %s\n", cli.c_str());
        return 1;
    }

    std::error_code ec;
    const fs::path dir = fs::temp_directory_path() / "jpssl_cmd_cert_rsa4096";
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    if (ec) {
        std::fprintf(stderr, "FAIL: 无法创建临时目录 %s: %s\n",
                     dir.string().c_str(), ec.message().c_str());
        return 1;
    }

    const fs::path tls_cert_der = dir / "tls_cert.der";
    const fs::path tls_key_pem  = dir / "tls_key.pem";
    const fs::path gen_cert_der = dir / "gen_cert.der";
    const fs::path gen_key_pem  = dir / "gen_key.pem";
    const fs::path log_file     = dir / "cmd.log";

    std::string out;
    std::printf("== jpssl-cert RSA-4096 端到端测试 ==\n");
    std::printf("CLI : %s\n临时目录: %s\n", cli.c_str(), dir.string().c_str());

    // ── a) tlsgen --key-type rsa4096 ──────────────────────────────────────
    std::printf("[a] tlsgen --key-type rsa4096\n");
    int rc = run_cmd(cli + " tlsgen --cn localhost --key-type rsa4096 --days 30 --out \"" +
                     tls_cert_der.string() + "\" --key-out \"" + tls_key_pem.string() + "\"",
                     log_file, out);
    TEST("tlsgen 退出码 0", rc == 0);
    TEST("tlsgen 输出含证书路径", out.find(tls_cert_der.string()) != std::string::npos);
    TEST("tlsgen 生成证书文件", fs::exists(tls_cert_der) && fs::file_size(tls_cert_der, ec) > 0);
    TEST("tlsgen 生成私钥文件", fs::exists(tls_key_pem) && fs::file_size(tls_key_pem, ec) > 0);

    // ── b) gen --key-type rsa4096 ─────────────────────────────────────────
    std::printf("[b] gen --key-type rsa4096\n");
    rc = run_cmd(cli + " gen --cn localhost --key-type rsa4096 --days 30 --out \"" +
                 gen_cert_der.string() + "\" --key-out \"" + gen_key_pem.string() + "\"",
                 log_file, out);
    TEST("gen 退出码 0", rc == 0);
    TEST("gen 输出含证书路径", out.find(gen_cert_der.string()) != std::string::npos);
    TEST("gen 生成证书文件", fs::exists(gen_cert_der) && fs::file_size(gen_cert_der, ec) > 0);
    TEST("gen 生成私钥文件", fs::exists(gen_key_pem) && fs::file_size(gen_key_pem, ec) > 0);

    // ── c) info --cert（证书公钥识别为 RSA-4096）──────────────────────────
    std::printf("[c] info --cert\n");
    rc = run_cmd(cli + " info --cert \"" + tls_cert_der.string() + "\"", log_file, out);
    TEST("info 退出码 0", rc == 0);
    TEST("info 输出含 RSA-4096", out.find("RSA-4096") != std::string::npos);

    // ── d) key --key（私钥识别为 RSA-4096，512 字节）──────────────────────
    std::printf("[d] key --key\n");
    rc = run_cmd(cli + " key --key \"" + tls_key_pem.string() + "\"", log_file, out);
    TEST("key 退出码 0", rc == 0);
    TEST("key 输出含 RSA-4096", out.find("RSA-4096") != std::string::npos);
    TEST("key 输出含 512 bytes", out.find("512 bytes") != std::string::npos);

    // ── e) 私钥 API 校验 ─────────────────────────────────────────────────
    std::printf("[e] private_key::from_pem\n");
    std::string key_pem;
    TEST("读取私钥 PEM 文件", read_file_text(tls_key_pem, key_pem) && !key_pem.empty());
    auto key = private_key::from_pem(key_pem);
    TEST("私钥解析成功", key.has_value());
    if (key) {
        TEST("私钥类型 RSA_4096", key->key_type == KeyType::RSA_4096);
        TEST("私钥 d 512 字节", key->priv.size() == 512);
        TEST("公钥 n||e 515 字节", key->pub.size() == 515);
        TEST("CRT p 256 字节且非零",
             key->rsa_p.size() == 256 && nonzero_bytes(key->rsa_p) > 0);
        TEST("CRT q 256 字节且非零",
             key->rsa_q.size() == 256 && nonzero_bytes(key->rsa_q) > 0);
        TEST("CRT dP 256 字节且非零",
             key->rsa_dP.size() == 256 && nonzero_bytes(key->rsa_dP) > 0);
        TEST("CRT dQ 256 字节且非零",
             key->rsa_dQ.size() == 256 && nonzero_bytes(key->rsa_dQ) > 0);
        TEST("CRT qInv 256 字节且非零",
             key->rsa_qInv.size() == 256 && nonzero_bytes(key->rsa_qInv) > 0);
    }

    // ── f) 证书 API 校验 ─────────────────────────────────────────────────
    std::printf("[f] x509_cert::from_der\n");
    std::vector<uint8_t> cert_der;
    TEST("读取证书 DER 文件", read_file_bytes(tls_cert_der, cert_der) && !cert_der.empty());
    auto cert = x509_cert::from_der(cert_der);
    TEST("证书解析成功", cert.has_value());
    if (cert) {
        TEST("证书公钥类型 RSA_4096", cert->key_type == KeyType::RSA_4096);
        TEST("证书公钥 515 字节", cert->public_key.size() == 515);
        TEST("证书在有效期内", cert->is_valid_now());
        TEST("证书自签名验签通过", cert->verify_signature(*cert));
    }

    // ── g) 服务端装载链路（tls_certificate::from_pem + RSA-PSS 签名）──────
    std::printf("[g] tls_certificate::from_pem + RSA-PSS-RSAE-SHA256\n");
    if (cert && key) {
        std::string cert_pem = cert->to_pem();
        auto sv = tls_certificate::from_pem(cert_pem, key_pem);
        TEST("from_pem 返回非空", sv != nullptr);
        if (sv) {
            TEST("rsa4096 标记为 true", sv->rsa4096);
            const char msg[] = "jpssl-cert rsa4096 e2e";
            uint8_t sig[512];
            size_t sig_len = 0;
            const uint16_t scheme = (uint16_t)SignatureAlgorithm::RSA_PSS_RSAE_SHA256;
            bool ok = sv->sign_scheme(scheme, (const uint8_t*)msg, sizeof(msg) - 1,
                                      sig, sig_len);
            TEST("RSA-PSS 签名成功", ok);
            TEST("RSA-PSS 签名长度 512", sig_len == 512);
            TEST("RSA-PSS 验签通过",
                 ok && sv->verify_scheme(scheme, (const uint8_t*)msg, sizeof(msg) - 1,
                                         sig, sig_len));
            if (ok) {
                sig[0] ^= 0x01;   // 篡改 1 字节
                TEST("篡改 1 字节后验签失败",
                     !sv->verify_scheme(scheme, (const uint8_t*)msg, sizeof(msg) - 1,
                                        sig, sig_len));
            }
        }
    }

    fs::remove_all(dir, ec);

    std::printf("\n结果: %d 通过, %d 失败\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
