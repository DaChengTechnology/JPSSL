/**
 * jpssl-crypt — 加密/解密/哈希/HMAC 命令行工具
 *
 * 用法:
 *   jpssl-crypt encrypt  --algo aes256gcm|chacha20 --key <hex> [--in <file>] [--out <file>]
 *   jpssl-crypt decrypt  --algo aes256gcm|chacha20 --key <hex> --in <file> --out <file>
 *   jpssl-crypt hash     --algo sha1|sha256|sha512|sha3-256|sha3-512|sm3 [--in <file>]
 *   jpssl-crypt hmac     --algo sha256|sha384|sm3 --key <hex> [--in <file>]
 *   jpssl-crypt b64encode [--in <file>] [--out <file>]
 *   jpssl-crypt b64decode [--in <file>] [--out <file>]
 */

#include "aes.hpp"
#include "base64.hpp"
#include "chacha20_poly1305.hpp"
#include "sha1.hpp"
#include "sha256.hpp"
#include "sha512.hpp"
#include "sha3.hpp"
#include "sm3.hpp"
#include "hmac.hpp"
#include "rand_os.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <span>

using namespace jpssl;

// ── helpers ────────────────────────────────────────────────────────────────
static void die(const char* msg) { std::fprintf(stderr, "ERROR: %s\n", msg); std::exit(1); }
static void usage() {
    std::printf(R"(jpssl-crypt — 加密/解密/哈希/HMAC 工具

用法:
  jpssl-crypt encrypt  --algo aes256gcm|chacha20 --key <hex-key> [--iv <hex>]
                       [--aad <hex>] [--in <file>] [--out <file>]
  jpssl-crypt decrypt  --algo aes256gcm|chacha20 --key <hex-key> [--iv <hex>]
                       [--aad <hex>] --tag <hex> --in <file> --out <file>
  jpssl-crypt hash     --algo sha1|sha256|sha512|sha3-256|sha3-512|sm3 [--in <file>]
  jpssl-crypt hmac     --algo sha256|sha384|sm3 --key <hex> [--in <file>]
  jpssl-crypt b64encode [--in <file>] [--out <file>]
  jpssl-crypt b64decode [--in <file>] [--out <file>]
  jpssl-crypt rand     <bytes>

算法:
  aes256gcm   AES-256-GCM AEAD (32-byte key, 12-byte IV, 16-byte tag)
  chacha20    ChaCha20-Poly1305 AEAD (32-byte key, 12-byte nonce, 16-byte tag)
  sha1        SHA-1 哈希 (20 bytes)
  sha256      SHA-256 哈希 (32 bytes)
  sha512      SHA-512 哈希 (64 bytes)
  sha3-256    SHA3-256 哈希 (32 bytes)
  sha3-512    SHA3-512 哈希 (64 bytes)
  sm3         SM3 密码杂凑 (32 bytes)

选项:
  --algo <name>   加密/哈希算法
  --key <hex>     密钥 (十六进制字符串)
  --iv  <hex>     IV/Nonce (十六进制, 默认随机生成)
  --aad <hex>     附加认证数据 (AEAD only)
  --tag <hex>     认证标签 (解密时需要, 十六进制)
  --in  <file>    输入文件 (默认 stdin)
  --out <file>    输出文件 (默认 stdout)
)");
}

static std::vector<uint8_t> hex_decode(const char* s) {
    std::vector<uint8_t> out;
    while (*s) {
        while (*s == ' ' || *s == '\n' || *s == ':') ++s;
        if (!*s) break;
        unsigned v;
        if (std::sscanf(s, "%2x", &v) != 1) die("无效 hex 字符串");
        out.push_back((uint8_t)v);
        s += 2;
    }
    return out;
}

static std::vector<uint8_t> read_all(FILE* f) {
    std::vector<uint8_t> data;
    uint8_t buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        data.insert(data.end(), buf, buf + n);
    return data;
}

static std::vector<uint8_t> read_file(const char* path) {
    if (!path || !std::strcmp(path, "-")) return read_all(stdin);
    FILE* f = std::fopen(path, "rb");
    if (!f) die("无法打开文件");
    auto data = read_all(f);
    std::fclose(f);
    return data;
}

static void write_file(const char* path, const std::vector<uint8_t>& data) {
    if (!path || !std::strcmp(path, "-")) {
        std::fwrite(data.data(), 1, data.size(), stdout);
        return;
    }
    FILE* f = std::fopen(path, "wb");
    if (!f) die("无法创建输出文件");
    std::fwrite(data.data(), 1, data.size(), f);
    std::fclose(f);
}

static void hex_out(const std::vector<uint8_t>& data) {
    for (auto b : data) std::printf("%02x", b);
    std::printf("\n");
}

static std::vector<uint8_t> rand_bytes(size_t n) {
    std::vector<uint8_t> out(n);
    // Windows BCrypt / Linux /dev/urandom
    jpssl::os_rand_bytes(out.data(), n);
    return out;
}

// ── AEAD encrypt ───────────────────────────────────────────────────────────
struct AEADParams {
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;       // 12 bytes
    std::vector<uint8_t> aad;
    std::vector<uint8_t> tag;      // 16 bytes (decrypt only)
};

static void aead_encrypt(const std::string& algo, const AEADParams& p,
                         const std::vector<uint8_t>& plain,
                         std::vector<uint8_t>& ct, std::vector<uint8_t>& tag) {
    if (algo == "aes256gcm") {
        if (p.key.size() != 32) die("AES-256 需要 32 字节密钥");
        aes_context ctx;
        ctx.init(std::span<const uint8_t, 32>(p.key.data(), 32));
        aes_gcm_encrypt(ctx, p.iv.data(), p.iv.size(),
                        std::span<const uint8_t>(plain),
                        std::span<const uint8_t>(p.aad),
                        ct, tag.data(), 16);
    } else if (algo == "chacha20") {
        if (p.key.size() != 32) die("ChaCha20-Poly1305 需要 32 字节密钥");
        chacha20_poly1305_encrypt(p.key.data(), p.iv.data(),
                                  std::span<const uint8_t>(plain),
                                  std::span<const uint8_t>(p.aad),
                                  ct, tag.data());
    } else {
        die("未知算法，支持: aes256gcm, chacha20");
    }
}

static bool aead_decrypt(const std::string& algo, const AEADParams& p,
                         const std::vector<uint8_t>& ct,
                         std::vector<uint8_t>& plain) {
    if (algo == "aes256gcm") {
        if (p.key.size() != 32) die("AES-256 需要 32 字节密钥");
        aes_context ctx;
        ctx.init(std::span<const uint8_t, 32>(p.key.data(), 32));
        return aes_gcm_decrypt(ctx, p.iv.data(), p.iv.size(),
                               std::span<const uint8_t>(ct),
                               std::span<const uint8_t>(p.aad),
                               p.tag.data(), 16, plain);
    } else if (algo == "chacha20") {
        if (p.key.size() != 32) die("ChaCha20-Poly1305 需要 32 字节密钥");
        return chacha20_poly1305_decrypt(p.key.data(), p.iv.data(),
                                         std::span<const uint8_t>(ct),
                                         std::span<const uint8_t>(p.aad),
                                         p.tag.data(), plain);
    } else {
        die("未知算法");
    }
    return false;
}

// ── subcommands ────────────────────────────────────────────────────────────

static void cmd_encrypt(int argc, char** argv) {
    std::string algo = "aes256gcm";
    const char *in_file = nullptr, *out_file = nullptr;
    std::vector<uint8_t> key, iv, aad;

    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--algo")) { if (++i < argc) algo = argv[i]; }
        else if (!std::strcmp(argv[i], "--key")) { if (++i < argc) key = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--iv")) { if (++i < argc) iv = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--aad")) { if (++i < argc) aad = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--in")) { if (++i < argc) in_file = argv[i]; }
        else if (!std::strcmp(argv[i], "--out")) { if (++i < argc) out_file = argv[i]; }
    }

    if (key.empty()) die("需要 --key <hex>");
    if (iv.empty()) iv = rand_bytes(12);  // auto-generate IV

    AEADParams p; p.key = key; p.iv = iv; p.aad = aad;
    auto plain = read_file(in_file);
    std::vector<uint8_t> ct, tag(16);
    aead_encrypt(algo, p, plain, ct, tag);

    // Format: IV (12) || ciphertext || tag (16)
    std::vector<uint8_t> out;
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());

    write_file(out_file, out);
    if (!out_file || !std::strcmp(out_file, "-")) {
        std::fprintf(stderr, "IV:  "); for (auto b : iv) std::fprintf(stderr, "%02x", b);
        std::fprintf(stderr, "\nTag: "); for (auto b : tag) std::fprintf(stderr, "%02x", b);
        std::fprintf(stderr, "\nSize: %zu bytes (plain=%zu, ct=%zu)\n", out.size(), plain.size(), ct.size());
    }
    if (out_file && std::strcmp(out_file, "-"))
        std::printf("加密完成: %zu bytes → %zu bytes (IV+CT+Tag)\n", plain.size(), out.size());
}

static void cmd_decrypt(int argc, char** argv) {
    std::string algo = "aes256gcm";
    const char *in_file = nullptr, *out_file = nullptr;
    std::vector<uint8_t> key, iv, aad, tag;

    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--algo")) { if (++i < argc) algo = argv[i]; }
        else if (!std::strcmp(argv[i], "--key")) { if (++i < argc) key = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--iv")) { if (++i < argc) iv = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--aad")) { if (++i < argc) aad = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--tag")) { if (++i < argc) tag = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--in")) { if (++i < argc) in_file = argv[i]; }
        else if (!std::strcmp(argv[i], "--out")) { if (++i < argc) out_file = argv[i]; }
    }

    if (key.empty()) die("需要 --key <hex>");
    if (tag.empty()) { /* tag will be extracted from file below */ }

    auto file_data = read_file(in_file);
    if (file_data.size() < 12 + 16) die("文件太小 (至少需要 12 字节 IV + 16 字节 tag)");

    // Format: IV (12) || ciphertext || tag (16)
    if (iv.empty()) {
        iv.assign(file_data.begin(), file_data.begin() + 12);
        file_data.erase(file_data.begin(), file_data.begin() + 12);
    }
    // Check if tag is embedded (last 16 bytes)
    if (file_data.size() >= 16) {
        // Use provided tag or embedded tag
        std::vector<uint8_t> ct(file_data.begin(), file_data.end() - 16);
        std::vector<uint8_t> embedded_tag(file_data.end() - 16, file_data.end());

        AEADParams p; p.key = key; p.iv = iv; p.aad = aad; p.tag = tag.empty() ? embedded_tag : tag;
        std::vector<uint8_t> plain;
        if (!aead_decrypt(algo, p, ct, plain))
            die("解密失败: 认证标签不匹配 (数据可能被篡改)");

        write_file(out_file, plain);
        std::printf("解密成功: %zu bytes → %zu bytes\n", file_data.size(), plain.size());
    }
}

static void cmd_hash(int argc, char** argv) {
    std::string algo = "sha256";
    const char* in_file = nullptr;

    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--algo")) { if (++i < argc) algo = argv[i]; }
        else if (!std::strcmp(argv[i], "--in")) { if (++i < argc) in_file = argv[i]; }
    }

    auto data = read_file(in_file);

    if (algo == "sha1") {
        uint8_t hash[20]; sha1_ctx ctx;
        sha1_init(&ctx); sha1_update(&ctx, data.data(), data.size()); sha1_final(&ctx, hash);
        hex_out(std::vector<uint8_t>(hash, hash + 20));
    } else if (algo == "sha256") {
        uint8_t hash[32]; sha256_ctx ctx;
        sha256_init(&ctx); sha256_update(&ctx, data.data(), data.size()); sha256_final(&ctx, hash);
        hex_out(std::vector<uint8_t>(hash, hash + 32));
    } else if (algo == "sha512") {
        uint8_t hash[64]; sha512_ctx ctx;
        sha512_init(&ctx); sha512_update(&ctx, data.data(), data.size()); sha512_final(&ctx, hash);
        hex_out(std::vector<uint8_t>(hash, hash + 64));
    } else if (algo == "sha3-256") {
        uint8_t hash[32]; sha3_ctx ctx;
        sha3_256_init(&ctx); sha3_update(&ctx, data.data(), data.size()); sha3_final(&ctx, hash);
        hex_out(std::vector<uint8_t>(hash, hash + 32));
    } else if (algo == "sha3-512") {
        uint8_t hash[64]; sha3_ctx ctx;
        sha3_512_init(&ctx); sha3_update(&ctx, data.data(), data.size()); sha3_final(&ctx, hash);
        hex_out(std::vector<uint8_t>(hash, hash + 64));
    } else if (algo == "sm3") {
        uint8_t hash[32]; sm3_ctx ctx;
        sm3_init(&ctx); sm3_update(&ctx, data.data(), data.size()); sm3_final(&ctx, hash);
        hex_out(std::vector<uint8_t>(hash, hash + 32));
    } else {
        die("未知哈希算法，支持: sha1, sha256, sha512, sha3-256, sha3-512, sm3");
    }
}

static void cmd_hmac(int argc, char** argv) {
    std::string algo = "sha256";
    const char* in_file = nullptr;
    std::vector<uint8_t> key;

    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--algo")) { if (++i < argc) algo = argv[i]; }
        else if (!std::strcmp(argv[i], "--key")) { if (++i < argc) key = hex_decode(argv[i]); }
        else if (!std::strcmp(argv[i], "--in")) { if (++i < argc) in_file = argv[i]; }
    }

    if (key.empty()) die("需要 --key <hex>");
    auto data = read_file(in_file);

    if (algo == "sha256") {
        uint8_t mac[32];
        hmac_sha256(key.data(), key.size(), data.data(), data.size(), mac);
        hex_out(std::vector<uint8_t>(mac, mac + 32));
    } else if (algo == "sha384") {
        uint8_t mac[48];
        hmac_sha384(key.data(), key.size(), data.data(), data.size(), mac);
        hex_out(std::vector<uint8_t>(mac, mac + 48));
    } else if (algo == "sm3") {
        uint8_t mac[32];
        hmac_sm3(key.data(), key.size(), data.data(), data.size(), mac);
        hex_out(std::vector<uint8_t>(mac, mac + 32));
    } else {
        die("未知 HMAC 算法，支持: sha256, sha384, sm3");
    }
}

static void cmd_rand(int argc, char** argv) {
    if (argc < 1) die("需要字节数, e.g. jpssl-crypt rand 32");
    size_t n = (size_t)std::atoi(argv[0]);
    if (n == 0 || n > 1024 * 1024) die("字节数超出范围 (1 ~ 1M)");
    auto r = rand_bytes(n);
    hex_out(r);
}

static void cmd_b64encode(int argc, char** argv) {
    const char *in_file = nullptr, *out_file = nullptr;
    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--in")) { if (++i < argc) in_file = argv[i]; }
        else if (!std::strcmp(argv[i], "--out")) { if (++i < argc) out_file = argv[i]; }
    }

    auto data = read_file(in_file);
    std::string b64 = base64_encode(data);

    if (out_file && std::strcmp(out_file, "-")) {
        write_file(out_file, std::vector<uint8_t>(b64.begin(), b64.end()));
        std::printf("Base64 编码完成: %zu bytes → %zu chars\n", data.size(), b64.size());
    } else {
        std::fwrite(b64.data(), 1, b64.size(), stdout);
        std::fputc('\n', stdout);
    }
}

static void cmd_b64decode(int argc, char** argv) {
    const char *in_file = nullptr, *out_file = nullptr;
    for (int i = 0; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--in")) { if (++i < argc) in_file = argv[i]; }
        else if (!std::strcmp(argv[i], "--out")) { if (++i < argc) out_file = argv[i]; }
    }

    auto data = read_file(in_file);

    // 容忍文本文件中的空白字符（行尾换行、空格、tab 等）
    std::string text;
    text.reserve(data.size());
    for (uint8_t c : data) {
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t')
            text.push_back((char)c);
    }

    auto decoded = base64_decode(text);
    if (!decoded) die("Base64 解码失败: 非法字符或格式不正确");

    write_file(out_file, *decoded);
    if (out_file && std::strcmp(out_file, "-"))
        std::printf("Base64 解码完成: %zu chars → %zu bytes\n", text.size(), decoded->size());
}

// ── main ───────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    const char* cmd = argv[1];

    if (!std::strcmp(cmd, "encrypt"))        cmd_encrypt(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "decrypt"))   cmd_decrypt(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "hash"))      cmd_hash(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "hmac"))      cmd_hmac(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "b64encode")) cmd_b64encode(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "b64decode")) cmd_b64decode(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "rand"))      cmd_rand(argc - 2, argv + 2);
    else if (!std::strcmp(cmd, "-h") || !std::strcmp(cmd, "--help")) usage();
    else { std::fprintf(stderr, "未知命令: %s\n", cmd); usage(); return 1; }
    return 0;
}
