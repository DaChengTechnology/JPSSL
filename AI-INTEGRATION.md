# jpssl AI 接入指南

> 这份文档写给 **AI 编程代理**（Codex / Cursor / Claude Code / Copilot 等）和想快速接入 jpssl 的工程师。
> 目标是让一个没有上下文的新 agent 在 5 分钟内能：看懂仓库 → 构建 → 写对第一个调用 → 不踩已知的坑 → 知道改完怎么验证。
> 配套的人读文档在 `wiki/`（`Home.md` / `Getting-Started.md` / `API-*.md`），本文件是它们的"AI 速查版"。

---

## 1. 一句话概览

jpssl 是一个 **C++17 跨平台密码学库**，无第三方运行时依赖：

- 对称加密：AES（ECB/CBC/GCM/CCM）、ChaCha20-Poly1305、SM4
- 哈希 / MAC / KDF：SHA-1/2/3、SM3、HMAC、HKDF
- 非对称：RSA-2048/4096、ECDSA P-256/384/521、Ed25519、Ed448、X25519、X448、SM2
- 协议：TLS 1.2/1.3（含 RFC 8998 国密套件）、DTLS 1.2/1.3、QUIC TLS 层、X.509 v3、证书透明（CT）
- 工具：`jpssl-cert`（证书）、`jpssl-crypt`（加解密）、`jpssl-test`（自测）

性能取向：x86 上自动分派 AES-NI / AVX2 / AVX-512 / SHA-NI / BMI2+ADX，P-256 有手写 x64 汇编（nistz256 结构）；ARM64 走 NEON/crypto 指令。

---

## 2. 仓库地图（AI 先看哪里）

| 路径 | 内容 | AI 行动 |
|---|---|---|
| `include/*.hpp` | 全部公共 API，**以头文件为准** | 写代码前先看对应头文件签名 |
| `src/*.cpp` | 实现；`src/*.asm` 是 MSVC x64 汇编 | 改算法时两端都要改 |
| `tests/` | 37 个 CTest 单测 + OpenSSL 互操作 | 改密码学代码后必须全绿 |
| `examples/https/` `examples/tls_socket/` | 最小可编译示例 | 抄 TLS socket 用法从这里开始 |
| `benchmarks/` | 与 OpenSSL 对比的基准 | 性能改动后跑 |
| `wiki/` | 人读文档（API 参考、平台构建、测试） | 细节查这里 |
| `threadpool/` | **独立 git 仓库**（协程线程池，CMake 按需 `add_subdirectory`） | 不要把它提交进 jpssl；它是子项目 |
| `build-win-test/` `build-*/` | 本地构建目录（gitignore） | 不要提交 |

命名空间约定：

```cpp
namespace jpssl {        // 纯算法：aes_* / sha256_* / ecdsa_p256_* / rsa_* / x25519_* ...
namespace jpssl::tls {   // TLS / DTLS / QUIC / socket 封装：tls_connection / tls_session ...
namespace jpssl::x509 {  // 证书：der 编解码 / pem / 证书链 ...
```

---

## 3. 构建（每个 AI 第一件事）

环境要求：CMake ≥ 3.20，C++11+（默认构建 C++17；MSVC 已验证 C++14/C++17/C++20，C++11 语法兼容、真实验证需 GCC/Clang，因 MSVC 无 C++11 模式），GCC 7+ / Clang 7+ / MSVC（VS 2019 16.10+ 或 2022+）；协程 I/O 需 C++20。库本身**不依赖 OpenSSL**（OpenSSL 只用于对比测试）。

### Linux / macOS

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### Windows（MSVC）

必须在 **x64 Native Tools / Developer PowerShell** 里执行：

```powershell
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win --parallel 12
ctest --test-dir build-win -C Release --output-on-failure
```

### 常用 CMake 选项

| 选项 | 默认 | 说明 |
|---|---|---|
| `JP_ENABLE_AVX2` / `JP_ENABLE_AVX512` | ON | x86 SIMD 加速 |
| `JP_ENABLE_NEON` | ON | aarch64 NEON/crypto |
| `JP_ENABLE_MUSA` | OFF | 实验性 GPU 加速（仅 Linux） |
| `JP_ENABLE_BENCH` | OFF | 构建 `benchmarks/` |
| `JP_ENABLE_OPENMP` | ON | RSA 批量并行 |
| `JPSSL_USE_EXTERNAL_THREADPOOL` | OFF | 父项目已提供 threadpool 头时置 ON，跳过 `add_subdirectory` |

### 产物与链接目标

| 产物 | CMake target | 说明 |
|---|---|---|
| `jpssl_cpu_static.lib` / `libjpssl_cpu.a` | `jpssl_cpu` | 静态库（首选） |
| `jpssl_cpu.dll` / `libjpssl_cpu.so` | `jpssl_cpu_shared` | 动态库 |
| `jpssl_musa` / `jpssl_musa_shared` | 同左 | 仅 `JP_ENABLE_MUSA=ON` |

消费者项目用 `add_subdirectory` 或 `FetchContent` 后直接 `target_link_libraries(app PRIVATE jpssl_cpu)`，头文件路径已 PUBLIC 传播。

### 手工编译单个探针/测试（Windows 踩坑记忆）

用 `cl.exe` 手工编译小工具时，仓库源文件含 **UTF-8 中文注释**，而 MSVC 默认按 GBK(936) 解释，会报奇怪错误：

```powershell
# 必须加 /std:c++17 /utf-8 /MD（库是动态运行时编译的）
cl /nologo /O2 /std:c++17 /EHsc /MD /utf-8 /I include my_probe.cpp `
  /link /LIBPATH:build-win-test\Release jpssl_cpu_static.lib ws2_32.lib bcrypt.lib
```

链接失败时先检查 RuntimeLibrary 是否匹配（`MD_DynamicRelease` vs `MT_StaticRelease`）。

---

## 4. 验证红线（改完代码必做）

**任何密码学/协议改动** 必须满足：

1. `ctest --test-dir build-win-test -C Release --output-on-failure` → **37/37 通过**
2. `build-win-test\tests\Release\test_openssl_compare.exe` → **22/22 通过**（与 OpenSSL 逐字节对比 SHA/HMAC/HKDF/AES-GCM/握手）

重点回归子集（按改动类型）：

- TLS 改动：`test_tls`、`test_tls_socket`、`test_tls_stability`、`test_tls_openssl_interop`（63s，最慢）
- QUIC 改动：`test_quic`、`test_quic_openssl_interop`、`test_quic_parser_compliance`
- DTLS 改动：`test_dtls`、`test_dtls_openssl_interop`、`test_dtls13_openssl_interop`
- 国密改动：`test_sm`、`test_tls_sm`
- 椭圆曲线改动：`test_ecdsa`、`test_x25519_ossl`、`test_x448_*`、`test_ed25519_*`、`test_ed448_*`
- RSA 改动：`test_rsa_pss`

**警告**：`test_tls_openssl_interop` 依赖本机 OpenSSL（对比目标），换机器/CI 需确认 OpenSSL 可用。

---

## 5. API 风格与约定（AI 必须遵守）

1. **无异常**：公共头文件零 `throw`。错误一律 `bool` 返回 + 可选的 `std::string* error = nullptr` 输出。
   ```cpp
   std::string err;
   if (!conn.connect(host, port, &mgr, &err)) { /* 处理失败 */ }
   ```
2. **输出缓冲区由调用方提供**：C 风格数组 + 长度常量，如 `uint8_t sig[64]`；大小常量以 `XXX_SIZE` 形式定义在头文件。
3. **`std::span` 用于只读数据输入**（AES 等），`std::vector<uint8_t>&` 用于变长输出。
4. **对齐敏感**：`aes_context` 要求 16 字节对齐（AES-NI 用 `__m128i` 访问轮密钥）；`rsa_bignum` 64 字节对齐。栈上/成员声明即可，不要自行 `memcpy` 到未对齐缓冲。
5. **密钥材料**：函数内局部变量不保证擦除；需要安全擦除时用 `secure_rand_bytes` 同级工具或显式 `OPENSSL_cleanse` 风格的清零。
6. **命名**：算法函数小写下划线（`aes_gcm_encrypt`、`ecdsa_p256_sign`），结构体小写下划线（`sha256_ctx`、`aes_context`）。
7. **线程安全**：纯算法函数无全局可变状态（可并行）；`tls_connection` 非线程安全；P-256 固定基预计算表（约 151 KB）首次签名/验签时惰性构建，当前是无锁双检（`g_nistz_pre_ready`），多线程并发首调会重复构建但结果一致——属良性竞态，如需严格保证可换成 `std::call_once`。

---

## 6. 快速示例（可直接编译）

以下代码都只依赖 `#include <jpssl 头文件>` + 链接 `jpssl_cpu`。

### 6.1 SHA-256

```cpp
#include "sha256.hpp"
#include <cstdio>

int main() {
    uint8_t digest[32];
    jpssl::sha256((const uint8_t*)"abc", 3, digest);
    std::printf("sha256(abc) = %s\n", jpssl::sha256_hex(digest).c_str());
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}
```

### 6.2 AES-GCM（AEAD）

```cpp
#include "aes.hpp"
#include <vector>

int main() {
    uint8_t key[32] = { /* 32B key */ };
    uint8_t iv[12]  = { /* 12B nonce */ };
    jpssl::aes_context ctx;
    ctx.init(std::span<const uint8_t, 32>(key));

    std::vector<uint8_t> pt = {'h','e','l','l','o'};
    std::vector<uint8_t> ct, back;
    uint8_t tag[16];
    jpssl::aes_gcm_encrypt(ctx, iv, sizeof(iv), pt, /*aad=*/{}, ct, tag);

    bool ok = jpssl::aes_gcm_decrypt(ctx, iv, sizeof(iv), ct, /*aad=*/{}, tag, sizeof(tag), back);
    return ok && back == pt ? 0 : 1;
}
```

### 6.3 ECDSA P-256 / Ed25519 / X25519

```cpp
#include "ecdsa.hpp"
#include "ed25519.hpp"
#include "x25519.hpp"

// P-256：pub 64B (x||y，无 0x04 前缀)，priv 32B，sig 64B (r||s)
uint8_t pub[64], priv[32], sig[64];
jpssl::ecdsa_p256_keygen(pub, priv);
jpssl::ecdsa_p256_sign(priv, (const uint8_t*)"msg", 3, sig);
bool ok = jpssl::ecdsa_p256_verify(pub, (const uint8_t*)"msg", 3, sig);

// Ed25519：priv 是 64B（seed+pub），不是 32B
uint8_t ed_pub[32], ed_priv[64];
jpssl::ed25519_keygen(ed_pub, ed_priv);
jpssl::ed25519_sign(ed_priv, msg, len, ed_sig);

// X25519：双方各自 keypair + scalar_mult 得共享密钥
uint8_t a_pub[32], a_priv[32], b_pub[32], b_priv[32], s1[32], s2[32];
jpssl::x25519_generate_keypair(a_pub, a_priv);
jpssl::x25519_generate_keypair(b_pub, b_priv);
jpssl::x25519_scalar_mult(s1, a_priv, b_pub);
jpssl::x25519_scalar_mult(s2, b_priv, a_pub);  // s1 == s2
```

注意：**ECDSA 与 EdDSA 的私钥长度/含义不同**（P-256 私钥 32B 标量；Ed25519 私钥 64B 含公钥）。这是最常见的接错点。

### 6.4 RSA

```cpp
#include "rsa.hpp"

jpssl::rsa_public_key  pub;
jpssl::rsa_private_key priv;
if (!jpssl::rsa_keygen(pub, priv)) return 1;   // 2048 位，约数百 ms

// 解密（私钥 CRT 快速路径）
std::vector<uint8_t> pt;
bool ok = jpssl::rsa_decrypt(priv, encrypted, pt);
```

`rsa_public_key`/`rsa_private_key` 在 `include/rsa.hpp`，`rsa_decrypt` 接受原始密文（大小 = 模长）。加解密封装（OAEP/PSS）与证书密钥解析在 `x509.hpp` / `tls_socket.hpp` 的 `tls_certificate`。

### 6.5 TLS socket（客户端）

```cpp
#include "tls_socket.hpp"

int main() {
    std::string err;
    if (!jpssl::tls::tls_socket_init(&err)) return 1;   // 必须先初始化（WSA/全局表）

    jpssl::tls::tls_connection conn;                    // 不可拷贝，只能移动
    if (!conn.connect("127.0.0.1", 4433, /*cert_mgr=*/nullptr, &err)) return 1;

    const char* req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (!conn.send((const uint8_t*)req, std::strlen(req), &err)) return 1;

    std::vector<uint8_t> resp;
    if (!conn.recv(resp, &err)) return 1;
    conn.close();
}
```

### 6.6 TLS socket（服务端 + 自签证书）

```cpp
#include "tls_socket.hpp"

int main() {
    std::string err;
    if (!jpssl::tls::tls_socket_init(&err)) return 1;

    // 自签 ECDSA P-256 证书
    jpssl::tls::tls_certificate cert;
    cert.subject_name = "localhost";
    cert.sig_alg = jpssl::tls::SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    jpssl::ecdsa_p256_keygen(cert.pub.ecdsa_p256, cert.priv.ecdsa_p256);
    // cert_data 留空时握手会自动生成自签名证书；显式填充可固定证书字节
    cert.cert_data = jpssl::tls::tls_make_x509_self_signed(cert, /*days=*/3650);

    jpssl::tls::tls_certificate_manager mgr;
    mgr.add_certificate("localhost", std::make_unique<jpssl::tls::tls_certificate>(cert));

    jpssl::tls::tls_listener listener;
    if (!listener.listen(4433, "127.0.0.1", &err)) return 1;

    jpssl::tls::tls_connection conn;
    if (!listener.accept(conn, mgr, &err)) return 1;   // 阻塞式，完成 TLS 握手后返回
    std::vector<uint8_t> req;
    if (!conn.recv(req, &err)) return 1;
    conn.close();
}
```

服务端证书的 `tls_make_x509_self_signed` 签名、`tls_certificate` 各字段以 `include/tls.hpp` + `include/tls_socket.hpp` 为准（细节有版本演进，别凭记忆写）。

---

## 7. TLS 内部语义（改 TLS 代码前必读）

### 7.1 `tls_session` 可拷贝，且存在 trial 回滚

`tls_socket.cpp` 客户端握手用 **4 处 `tls_session trial = session_;` 拷贝 + 成功后 `session_ = std::move(trial)`** 实现 flight 回滚。因此：

- `tls_session` 必须保持**可拷贝**；
- 新增大块成员时优先用 `std::shared_ptr<T>` 惰性分配（如 `rsa_key`、`dhe_keys`、`quic_secrets`），**不要**用 `std::unique_ptr`（会让 `tls_session` 不可拷贝，编译直接失败）；
- 往成员里写状态时想清楚：trial 与 session 共享的 shared_ptr 目标，写操作在回滚后仍会保留（现状靠"这些字段只在非 trial 路径/非 QUIC 路径写入"保证正确性，别破坏这个前提）。

### 7.2 内存优化过的字段（不要退回大数组）

| 字段 | 类型 | 何时分配 |
|---|---|---|
| `rsa_key` | `shared_ptr<rsa_private_key>` | TLS 1.2 服务端 RSA/ECDHE-RSA 套件 |
| `dhe_keys` | `shared_ptr<tls12_dhe_keys>` | TLS 1.2 DHE 套件 |
| `quic_secrets` | `shared_ptr<quic_secrets_block>` | `quic_mode` 会话 |

普通 TLS 1.3 连接这些指针全为空（省约 2.5 KB/连接）。访问前要判空（代码里已有 `if (!s.rsa_key || ...)` 模式）。

### 7.3 QUIC / DTLS

- QUIC：设置 `s.quic_mode = true` 后握手走 CRYPTO 帧（无记录层），传输参数在 `quic_transport_params` / `quic_peer_transport_params`（公开内嵌结构，别改成指针——测试和 README 直接访问成员）。
- DTLS：`dtls.hpp` 提供数据报握手；与 OpenSSL 4（DTLS 1.2）和 wolfSSL 5.9.2（1.2/1.3）互通。

### 7.4 握手临时数据

握手期会用到 `client_random/server_random`、`handshake_secret/master_secret`、traffic secrets、`transcript_ctx_union` 等内嵌数组（总计约 1.6 KB）。这些是运行必需，**不要**为了省内存随便改成堆分配——trial 拷贝语义和常量时间要求会让这类改动风险极高。

---

## 8. 性能与汇编约定

### 8.1 运行时自动分派

`src/*_auto.cpp`（如 `aes_gcm_auto.cpp`）在首次调用时用 `cpu_features.hpp` 检测指令集，选择最优实现。新增 SIMD 变体时：

- 检测逻辑加在 `cpu_features.hpp` / `jpssl_platform.hpp`；
- 把新实现挂进对应 `*_auto` 分派函数；
- 在 `benchmarks/` 加对比项，并与 OpenSSL 同算法基准比较；
- 至少跑 `test_openssl_compare` 验证逐字节一致。

### 8.2 MSVC x64 汇编（`src/*.asm`）

- 文件用 MASM 语法（`ml64` 编译，`extern "C"` 在 C++ 侧声明）；
- Win64 调用约定：**shadow space 32B + 栈 16 字节对齐**，被调方保存 `rbx/rsi/rdi/rbp/r12-r15`；
- `EQU` 符号**全文件不得重名**（MASM 全局命名空间）；
- 新增 `.asm` 必须追加到 `CMakeLists.txt` 的 `CPU_SOURCES`（MSVC 分支），否则只在你本机构建成功、别人构建找不到符号；
- 纯汇编微基准（如 `p256_micro_probe`）比整体基准稳定，性能验证优先用它。

### 8.3 性能基准波动

机器上有后台扫描等进程时，签名/验签微基准波动可达 ±30%。结论要取多轮最优值或多次中位数，不要用单次数据下结论。

---

## 9. 提交与 git 卫生

- 提交信息用 conventional commits 风格（仓库历史如此）：
  `perf(ecdsa): ...` / `fix(aes-gcm): ...` / `feat(tls): ...` / `chore(ci): ...`；
- **不要提交**：`build-*/`、`threadpool/`（独立仓库）、`*.txt` 测试输出、`*.obj`、`*.initial`、个人文档（如 `知乎推广文章.md`）；
- 提交前 `git status` 人工核对暂存文件列表，用显式路径 `git add`，避免 `git add -A` 误收；
- 改密码学代码必须过 §4 的红线再提交。

---

## 10. 常见坑速查表

| 现象 | 原因 | 解法 |
|---|---|---|
| MSVC 手工编译报 `hex 未声明`/乱码 | 源文件 UTF-8 中文注释被当 GBK 解析 | `cl` 加 `/utf-8` |
| `LNK2038 RuntimeLibrary 不匹配` | 库是 `/MD` 编译，你的探针是 `/MT` | `cl` 加 `/MD` |
| `std::span 不是 std 成员` | 缺少兼容头 | 项目内置 `jpssl_span.hpp`（`jpssl::span`），无需手改 |
| `tls_session` 拷贝编译失败 | 有人把成员改成了 `unique_ptr` | 用 `shared_ptr` 或深拷贝 |
| TLS 1.2 RSA 握手失败/空密钥 | `rsa_key` 未分配 | 检查 `tls12_make_server_flight` 注入路径 |
| P-256 汇编符号找不到 | `.asm` 没加进 `CMakeLists.txt` | 追加 `CPU_SOURCES` 并重新 configure |
| 改了 QUIC 字段后测试/README 编译失败 | 把公开结构改成了指针 | `quic_transport_params` 保持内嵌 |
| 单测全绿但 `test_openssl_compare` 失败 | 与 OpenSSL 字节不一致 | 查端点序/填充/标签长度 |

---

## 11. 给 AI 的工作流建议（推荐顺序）

1. `git status` + `git log --oneline -5` 确认基线；
2. 读相关头文件（`.hpp`）确定签名，不要猜；
3. 小步改动，先编译目标库再编译测试；
4. 跑 §4 红线（37/37 + 22/22）；
5. 性能改动跑对应 `benchmarks/` 或微探针；
6. 提交前核对 `git status` 暂存清单；
7. 推送前确认远端（origin = 内网 git.jphc.cn，github = 公开镜像）。
