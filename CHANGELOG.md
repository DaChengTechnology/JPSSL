# Changelog

## [1.1.8] - 2026-08-14

### Added
- **jpssl-cert 私钥默认输出 PKCS#8 PEM**：`gen` / `tlsgen` 的 `--key-out`
  默认输出 `-----BEGIN PRIVATE KEY-----`（与 openssl genpkey 一致），
  `--key-format der` 可切换为 PKCS#8 DER。Ed25519/Ed448 为 RFC 8410，
  ECDSA/SM2 内嵌 SEC1 ECPrivateKey（含 `[1]` 公钥），RSA 内嵌完整
  PKCS#1 参数（n/e/d/p/q/dP/dQ/qInv）。

### Fixed
- **TLS 证书链验证（ECDSA/Ed25519 证书握手失败）**：服务端链验证改为标准
  信任锚逻辑，支持交叉签名链尾（如 Cloudflare 的 GTS Root R4 由 GlobalSign
  Root CA 签发）与 SHA-1 自签旧根，不再强制链尾证书自签且自签验证必须通过
  （RFC 5280 §6.1，信任锚按配置信任）。
- **TLS 1.2 加密 alert 处理**：应用阶段收到加密的 close_notify（记录头
  type=21、载荷为密文）时正确解密并视为优雅关闭，返回已收数据，修复
  “握手成功后数据交换报 TLS alert received”问题。
- **TLS 1.2 Ed25519/Ed448 证书**：纳入 ECDHE-ECDSA 套件族，修复
  “wrong certificate type”导致的握手失败。
- **X.509 from_pem 保留原始 DER**：避免证书链验证失败（同步自
  feature/co-threadpool）。
- **ECDSA P-256 g_comb 定点表**：签名前确保已构建，修复直接签名死循环
  （同步自 feature/co-threadpool）。

### Perf
- **SM4-CCM GFNI 加速**：新增运行时自动派发（GFNI > 标量），CTR 阶段复用
  8 路并行 GFNI 引擎（CCM 计数器语义：末 15-nonce_len 字节自增），CBC-MAC
  串行链与 CTR 融合为单趟处理；16 MiB 单线程加密 172 ms → 118 ms（约 1.46x），
  解密约 1.43x。SM4-CCM 单元测试（独立参考实现 + 600 组合标量/auto/GFNI
  一致性矩阵）与 TLS 回归均通过。

## [1.1.7] - 2026-08-13

### Added
- **第三方 TLS 实现全量多长度互操作测试**（在 DTLS 1.2/1.3 wolfSSL 互操作之上扩展）：
  - OpenSSL SM2 证书服务端互通（SM2-SM4-SM3 全链路）；
  - SM2-SM4-SM3（RFC 8998）与 wolfSSL 双向互通；
  - wolfSSL TLS 1.2/1.3 全量多长度互通：30 套件 × 2 方向 × 31 长度，
    含大量非 8 字节对齐边界（1..17、31/32/33、…、65535/65536/65537）；
  - Mbed TLS 3.6 TLS 1.2/1.3 互操作（`test_tls_mbedtls_interop`，
    `-DJP_MBEDTLS_PREFIX` 注入安装前缀，30 套件 × 2 方向 × 31 长度）；
  - rustls 0.23（ring provider）TLS 1.2/1.3 互操作（`tools/rustls_interop`
    Rust 独立实现，覆盖 rustls 支持的 9 套件 × 2 方向 × 31 长度）。
- **DTLS 服务器/客户端示例**（`examples/dtls/`）：`dtls_server` / `dtls_client`，
  基于 `dtls_connection` 的 UDP 回显演示，支持 DTLS 1.2/1.3、密码套件、
  密钥交换组、cookie 交换（HelloVerifyRequest）与 PEM 证书加载；
  未提供证书时内存生成 ECDSA P-256 自签证书，开箱即用。
- **SM4-GCM 算法路由与加速后端**：
  - 运行时算法路由（GFNI > AVX2 > 标量），TLS 1.3 记录层接入；
  - GFNI 常量时间 S-Box 后端（VGF2P8AFFINEQB / VGF2P8AFFINEINVQB），
    SM4-GCM 提速 2.85×；
  - GHASH 4 路并行 PCLMULQDQ，GHASH 提速 2.0×。
- **TLS/DTLS 记录层 fuzz 测试**：`test_tls_record_fuzz` /
  `test_dtls_record_fuzz` / `test_tls_handshake_fuzz`，并修复 5 处内存安全缺陷。
- **系统信任库证书校验**：Windows ROOT 库加载、RSA-PSS（SHA-256/384/512）
  与 RSA-4096 链验证。

### Fixed
- **TLS 1.3 记录填充解析（RFC 8446 §5.2）**：`TLSInnerPlaintext` 允许内容
  类型字节后追加零填充；此前假定 type 为最后一个字节，Mbed TLS 填充记录
  会解密失败。
- **TLS 1.2 套件协商**：仅从客户端通告列表中选择并拒绝未知套件；TLS 1.2
  不再接受 SM4 套件（TLS 1.2 协议不支持 SM4）。
- **AES-GCM VAES counter 进位**：修复 8 块流水 counter 递增 bug 与跨
  255→256 进位丢失（长消息 ≥4096B 密文错误）。
- **TLS socket**：恢复 Windows localhost 阻塞 connect 语义；握手 I/O 受
  握手超时约束，服务端 flight 异常时快速失败。

### Perf
- **内存优化**：
  - `dtls_session`：内嵌 2688B `tls_certificate` 改为 `shared_ptr` 按需堆分配，
    握手互斥布尔合并为 uint8 阶段枚举，3840B → 1112B（-71%）；
  - `tls_session`：按成员对齐重排消除全部填充空隙，2976B → 2912B。
- **P-256 ECDSA**：comb_mul_G 固定点汇编（Linux/macOS x86-64）+ ADX 内联
  汇编加速。
- **X25519**：fe51（radix-2^51）域运算汇编原语（移植 OpenSSL
  x25519-x86_64.pl）。
- **批量 ECDH**：OpenMP 线程数按 CPU 核数自适应；HMAC 微优化。

## [1.1.0] - 2026-08-08

### Added
- **DTLS 1.2 / 1.3 与 wolfSSL 互操作合规性测试**：
  - 新增 `tests/test_dtls_wolfssl_interop.cpp`（CTest 目标 `test_dtls_wolfssl_interop`）：
    jpssl 与 wolfSSL（5.9.2，DTLS 1.2/1.3，AES-128-GCM / ChaCha20-Poly1305）双向互通，
    共 4 套件 x 2 方向 = 8 用例，全部通过；覆盖证书链双向校验与握手后应用数据。
  - 构建时通过 `JP_WOLFSSL_PREFIX` / `JP_WOLFSSL_CERT_DIR` 注入 wolfSSL 安装前缀与测试证书目录。
- **DTLS 1.2（RFC 6347）合规修复**：
  - 客户端按服务器 ServerKeyExchange 选择的曲线重新生成 ECDHE 密钥对（此前固定默认曲线，
    服务器选 P-256 时会发出 Y 坐标全零的非法点，wolfSSL 实测拒绝）。
  - 客户端会话持久化已解析的服务器证书链（RFC 6347 允许每条握手消息独立数据报，
    此前跨数据报会丢失证书导致 SKE 校验失败）。
- **DTLS 1.3（RFC 9147 / RFC 8446）合规修复**：
  - P-256 key_share 修正为 65 字节未压缩点（`0x04 || X || Y`，RFC 8446 4.2.8.2）。
  - ServerHello 中 supported_versions 修正为单个 ProtocolVersion（RFC 8446 4.2.1）。
  - 密钥调度补齐 `Derive-Secret(Early Secret, "derived", "")` 中间步骤（RFC 8446 7.1）。
  - CertificateVerify 签名内容修正为 `64 x 0x20 || context || 0x00 || transcript_hash`
    （RFC 8446 4.4.3）；Finished 密钥改为从 handshake traffic secret 派生（4.4.4）。
  - 记录解密放宽最小密文长度检查（wolfSSL 不填充明文到 16 字节）。
- **X.509（RFC 5280）合规修复**：ECDSA / SM2 证书签名改为 DER 编码的
  ECDSA-Sig-Value（此前写入定长 raw r||s，wolfSSL 严格按标准拒绝）。

### Fixed
- 修复 TLS 1.3 CertificateVerify ECDSA 签名格式回归：保持 DER 编码（OpenSSL 4.0 /
  wolfSSL 均按 DER 校验；RFC 8446 的 raw 格式实测会被拒绝）。

### Added
- **iOS 实现（最低 iOS 13.0，仅 arm64 / ARMv8）＋ Swift 符号导出**：
  - 新增 `cmake/toolchains/ios-arm64.cmake` 交叉编译 toolchain：`IOS_SDK`
    （`iphoneos` / `iphonesimulator`）选择 SDK，锁定
    `CMAKE_OSX_ARCHITECTURES=arm64`（纯 ARMv8 64 位，无 armv7/x86_64 slice）、
    `CMAKE_OSX_DEPLOYMENT_TARGET=13.0`（iOS 13 起仅支持 64 位设备，天然 ≥ ARMv8）；
    NEON 源默认 `-march=armv8-a+crypto`（可用 `-DJP_ARM_MARCH` 覆盖），
    SHA-512/SHA-3/SM3/SM4 扩展源单独 armv8.4-a + 运行时 `cpu_features` 分派，
    低版本芯片安全回退标量；OpenMP / MUSA 自动关闭；
  - 新增 `ios/bridge/` Swift 符号桥接层：`jpssl.h`（纯 C、`extern "C"` 全 API 面）＋
    `jpssl_bridge.cpp`（实现）＋ `module.modulemap`（Clang 模块 `JPSslC`），
    iOS 构建时自动编入静态库 `libjpssl_cpu.a`（CMakeLists 按
    `CMAKE_SYSTEM_NAME=STREQUAL iOS` 追加源与 include 路径）；
  - 覆盖算法：SHA-1/256/384/512、SHA3、SHAKE128/256、SM3、HMAC、HKDF、
    AES（ECB/CBC/GCM/CCM/GHASH）、ChaCha20-Poly1305、SM4（CBC/GCM/CCM）、
    X25519/X448、Ed25519/Ed448、ECDSA P-256/384/521、SM2、RSA-2048/4096
    （PKCS#1 v1.5、OAEP、PSS、PKCS1v15）、X.509 证书解析/验签、TLS 1.3 高层
    socket 连接（`tls_connection` 封装）、Base64；
  - 新增 `ios/Sources/JPSsl/JPSsl.swift` 惯用 Swift API（`JPSsl.Hash/AES/RSA/…`）；
  - 新增 `ios/build-xcframework.sh`：CMake 构建真机 + Apple Silicon 模拟器切片、
    组装 `JPSslC.framework`（Headers/Modules/Info.plist）、
    `xcodebuild -create-xcframework` 产出 `ios/JPSsl.xcframework`；
  - 新增 `ios/Package.swift`（Swift Package，binaryTarget 引用 XCFramework，iOS 13+）；
  - `.github/workflows/ios.yml`：macOS runner 上执行构建并做 Swift 编译冒烟测试；
  - README 新增 iOS 集成说明（`ios/README.md`）。
- **HarmonyOS / OpenHarmony（鸿蒙 7.0）实现**：
  - 新增 `cmake/toolchains/ohos.cmake` 交叉编译 toolchain：自动定位 HarmonyOS NDK
    （`-DOHOS_NDK_HOME` → `$OHOS_NDK_HOME` → `$DEVECO_SDK_HOME`），支持
    `OHOS_ARCH`（arm64-v8a 默认 / armeabi-v7a / x86_64）与 `OHOS_STL`，产出
    `libjpssl_cpu.a` / `libjpssl_cpu.so`；
  - `CMakeLists.txt` 新增 `JP_OHOS` 目标平台判定（`CMAKE_SYSTEM_NAME=OHOS`）：
    只构建库，测试/命令行工具/示例/基准自动跳过（OpenHarmony NDK 面向应用
    native 模块，不提供可执行文件链接运行时）；OpenMP、MUSA GPU（仅 Linux）
    自动禁用；arm64-v8a 全量启用 NEON/crypto 硬件加速（含 `ecp_nistz256_arm.S`）；
  - `rand_os.cpp`：鸿蒙随机源优先 `getrandom()`（musl），失败回退 `/dev/urandom`；
  - `cpu_features.hpp`：ARM 特性检测识别 `__OHOS_FAMILY__`/`__OHOS__`（同为
    Linux 内核，走 `getauxval`），以 `__has_include` 容错缺失 `<asm/hwcap.h>`
    的鸿蒙 sysroot 并手动补齐 HWCAP/HWCAP2 位定义；
  - README 新增鸿蒙构建与工程集成说明。
- **QUIC v1 / v2 SSL 支持（RFC 9000/9001/9369）**：为 QUIC 提供必要的 TLS 1.3 支持，
  TLS 握手不再使用记录层（无 record 头 / 无 ChangeCipherSpec），握手消息以原始
  TLS Handshake 字节流交付给 QUIC CRYPTO 帧：
  - `tls_quic_make_client_hello` / `tls_quic_make_server_flight` /
    `tls_quic_process_server_flight` / `tls_quic_process_client_finished`
    （及 `tls13_make_quic_*` 便捷包装），ClientHello 与 EncryptedExtensions
    自动携带 `quic_transport_parameters`（0x0039）扩展，缺少该扩展时拒绝握手；
  - `quic_transport_parameters` 结构（RFC 9000 §18）完整编解码：全部标准参数
    （0x00–0x10）＋未知/扩展参数原样保留，含 RFC 9000 §16 varint 编解码
    （`quic_varint_encode/decode`）；
  - Initial 数据包保护密钥 `tls_quic_derive_initial_secrets`：v1 盐
    `0x38762cf7…`、v2 盐 `0x0dede3de…`（RFC 9001 §5.2 / 9369 §3.3.1）；
  - 握手/1-RTT 数据包保护密钥：`tls_quic_get_handshake_keys` /
    `tls_quic_get_application_keys` 与 `tls_quic_derive_packet_keys`
    （v1 标签 "quic key/iv/hp"，v2 标签 "quicv2 key/iv/hp"，RFC 9369 §3.3.2）；
  - 头部保护掩码 `tls_quic_header_protection_mask`（AES-ECB / ChaCha20，RFC 9001 §5.4）；
  - `tls_session` 新增 `quic_mode` / `quic_version` / `quic_transport_params` /
    `quic_peer_transport_params` 及 QUIC secret 状态，`tls13_derive_*` 在
    `quic_mode` 下自动派生 "client in"/"server in" 流量 secret。
- **DTLS 1.2 / DTLS 1.3（RFC 6347 / RFC 9147）标准数据报 TLS**：
  - 新增 `include/dtls.hpp` / `src/dtls.cpp`，完整实现 DTLS 记录层与握手：
  - DTLS 记录层：1.2（`type||version||epoch||seq||len` 13 字节头）与 1.3
    （unified header + 记录号加密，RFC 9147 §4）两种格式，epoch/序列号
    滑动窗口、AEAD（AES-128/256-GCM、ChaCha20-Poly1305）、1.2 的
    GCM salt(4) 与 ChaCha20 fixed-IV(12) nonce 构造；
  - DTLS 1.2 握手：HelloVerifyRequest cookie 交换、message_seq 与
    分片/重组、ChangeCipherSpec、ECDHE（X25519/P-256）密钥交换、
    TLS 1.2 PRF（P_SHA256/384）密钥派生、Finished（12 字节 verify_data）；
  - DTLS 1.3 握手：复用 TLS 1.3 消息（"dtls13" HKDF 标签前缀，RFC 9147 §5.9）、
    DTLSHandshake 分帧、ACK 记录（content type 26）、记录号加密、
    握手/1-RTT 应用流量密钥、CertificateVerify（Ed25519/ECDSA/RSA-PSS）；
  - 步进式握手状态机 `dtls_handshake_step`（datagram in → datagram out，
    支持同一数据报内先握手消息后加密记录的密钥就绪重试）；
  - `dtls_connection`：UDP socket 封装（`connect` / `bind`+`server_handshake` /
    `send` / `recv`），含握手超时重传、首个数据报 recvfrom 学习对端地址。

### Tests
- 新增 `test_dtls`（CTest 目标）：DTLS 1.2/1.3 内存数据报握手 × AES-128-GCM /
  AES-256-GCM(SHA-384) / ChaCha20，X25519/P-256/X448 密钥交换，cookie 交换，
  双向应用数据（含 10/20KB 大消息分片）、记录格式与篡改拒绝、
  x509 链验证（正确 CA 通过 / 错误 CA 拒绝）、UDP socket 端到端握手与数据
  交换，共 54 项全部通过；全套 32 个 CTest 无回归。
- 新增 `test_quic`（CTest 目标）：RFC 9001 A.1 / RFC 9369 A.1 Initial 密钥、
  RFC 9001/9369 A.5 1-RTT 密钥（ChaCha20）、头部保护掩码测试向量全部逐字节匹配；
  transport parameters 编解码往返与非法值拒绝；QUIC v1/v2 × AES-128-GCM/ChaCha20
  完整握手往返（含 x509 链验证、X448 密钥交换），客户端与服务端派生的数据包
  保护密钥逐字节一致；缺少 `quic_transport_parameters` 扩展被拒绝，共 86 项全部通过；
  全套 30 个 CTest 无回归。
- **DHE（ffdhe2048）性能优化**：`ffdhe2048_keypair` / `ffdhe2048_shared` 改用
  全局缓存的 Montgomery 上下文（R/R2/m' 按固定模数 p 只算一次）+ 4-bit 窗口
  模幂（`rsa_mont_modpow_win`），替代每次调用重算 R/R2 的朴素平方-乘
  `bn_modpow`；实测单次 keypair 约 393→224 µs、shared 约 389→224 µs
  （≈1.75×，x86-64 Release / MSVC）。

- **TLS 1.2 新增 DHE 与 PSK 密钥交换**：支持 DHE-RSA（ffdhe2048，RFC 7919）、
  纯 PSK（RFC 4279）与 DHE-PSK（RFC 5487）共 15 个新密码套件
  （GCM×6 / ChaCha20-Poly1305×3 / AES-CBC×6），含服务端/客户端双向握手、
  ServerKeyExchange、ClientKeyExchange 与 premaster 派生；CBC 记录层按
  RFC 5246 6.2.3.1/6.2.3.2 重写（seq‖type‖ver‖len 的 HMAC 输入与 TLS 填充格式），
  PSK premaster 采用 OpenSSL 兼容格式（纯 PSK 时 other_secret 为 psklen 个零字节）。
- **TLS 1.2 socket 层客户端握手**：`tls_connection::set_tls_version(TLSVersion::V12)`
  后 `connect()` / `client_handshake()` 执行完整 TLS 1.2 客户端握手
  （ClientHello → ServerHelloDone → ClientKeyExchange → CCS → Finished），
  支持 RSA / ECDHE / DHE / PSK / DHE-PSK 全部 25 套件；会话重置时保留
  TLS 1.2 PSK 配置（`tls12_psk_*`）。
- **TLS 1.2 ECDHE 扩展**：客户端 `supported_groups` 通告 X25519 + P-256/P-384 +
  ffdhe2048，`tls12_process_server_flight` 支持 P-256/P-384 临时密钥的
  ServerKeyExchange 解析与 premaster 派生（ECDSA 证书曲线须在客户端通告组内，
  否则 OpenSSL 报 no shared cipher）。
- **TLS 1.2 OpenSSL 互操作测试扩展**：`test_tls_openssl_interop` 覆盖 25 套件 ×
  2 方向（jpssl 服务端↔OpenSSL 客户端、OpenSSL 服务端↔jpssl 客户端 socket 层），
  共 50 用例全部与 OpenSSL 4.0 互通。

- **TLS socket 托管外部 fd**：`tls_connection::attach(fd, take_ownership=true)`
  接管调用方已创建的 socket（TCP 已连接 / accept 出的连接 / UDP 已 connect 或已 bind），
  并在其上完成握手；`take_ownership=false` 借用模式不关闭外部句柄；
  新增 `client_handshake()` 在已托管 socket 上发起客户端握手（不重建传输），
  `tls_listener::attach()` 托管外部监听 socket。
- **TLS over UDP（数据报模式）**：每条 TLS record 封装为一个 UDP 数据报
  （UDP 发送原子性保证整包传输，单条 record ≤ 16KiB+256），握手与应用数据
  统一走该约定，`send()` 大消息自动分片多数据报、`recv()` 自动合并还原；
  服务端 `listen_udp()` + `accept_udp()`（首包 recvfrom 取对端地址、监听 socket
  本身 connect 固定对端以保持源端口、随后转交连接），客户端 attach UDP fd 后
  `client_handshake()` 即用；`attach` 对 `SOCK_DGRAM` 自动启用，也可
  `set_datagram_mode()` 显式覆盖。

### Tests
- `test_tls_socket` 新增外部 TCP fd 托管（attach + client_handshake 双向收发）、
  借用模式（close() 不关闭外部 fd）、UDP 回环（含 40000 字节大消息跨数据报
  自动合并）用例，共 79 项全部通过；TLS 相关测试套件无回归。

## [1.0.0] — 2026-08-06

首个 1.0 正式版（CMake `project(jpssl VERSION 1.0.0)`）。

### Performance
- **ECDHE 批量加速（第二种方案）**：新增 `ecdsa_p256_ecdh_batch` / `ecdsa_p384_ecdh_batch`
  批量 API，块内 2 次求逆摊薄模逆成本；实测 P-256 批量 1.20×、P-384 1.27× 吞吐提升，
  P-384 批量反超 OpenSSL；新增 `bench_ecdh_batch` 基准。
- **P-256 点运算汇编无分支化（常数时间）**：`jpssl_p256_dbl/madd` 特殊归约的
  cmp/ja/jb 条件跳转改为 setc+neg+cmov 掩码，消除点运算对密钥数据的时序依赖；
  真实随机密钥 ECDH 场景 −9%，标准基准吞吐持平。
- **P-256 专用加法链求逆（255 sq + 12 mul）+ ADX 汇编**：新增 `jpssl_p256_inv_adx`
  （与 crypto/internal/nistec/fiat/p256_invert.go 同源，addchain v0.4.0）；
  `mod_inv p` 4.27 µs → 2.89 µs（1.47×），固定密钥 ECDH 48.7 → 46.7 µs；
  整条链无数据相关分支，常数时间。

### Fixed
- **TLS socket 的 Windows 编译修复**：`pollfd` 列表初始化在 winsock2.h 的
  `SOCKET fd` 下触发 C2397 窄化，改为成员赋值。
- **协程 double-free 修复**：`tls_co_task::await_resume` 销毁内层协程帧后置空句柄，
  防止临时任务对象析构对同一帧二次 destroy（flaky 堆损坏根因）；配合全量重建，
  `test_tls_socket` 连续 43 次通过。
- **X.509 version 字段语义修正（RFC 5280）**：`to_der()` 此前将内部 `version`（0=v1, 1=v2, 2=v3）减 1 后编码（`INTEGER version-1`），导致 v3 证书被编码为 `[0] INTEGER 1`（实际为 v2），与 OpenSSL 互操作时版本降级；`from_der()` 解析时 +1 回填，round-trip 内部自洽但与标准不符。现改为直接编码 `INTEGER version`、解析直接取 `INTEGER` 值。
- **v1 证书 round-trip 字节一致**：`from_der()` 解析无 version 字段的 v1 证书时残留 builder 默认 `version=2`，`to_der()` 重编码会凭空多出 `[0] INTEGER 1` 字段（+5 字节）且语义升为 v2。现解析 v1 证书显式置 `version=0`，round-trip 与 OpenSSL 原始 DER 逐字节一致（247→247 bytes 已验证）。

### Added
- **`jpssl-cert gen/tlsgen` 默认输出到 `~/.ssh`**：证书默认写 `~/.ssh/cert.der`、私钥写 `~/.ssh/key.bin`（自动创建目录；私钥权限 0600；`--out`/`--key-out` 仍可指定其他位置并支持 `~` 展开）。
- **PEM 证书读取**（`x509_cert::from_pem` / `to_pem`）：解析 `-----BEGIN CERTIFICATE-----` 包裹的 base64 DER，与 `from_der` 完全兼容（base64 使用库内 `jpssl::base64_decode` / `base64_encode`，无外部依赖）。
- **私钥读取**（`private_key::from_pem` / `from_der`）：自动识别 PKCS#8（`BEGIN PRIVATE KEY`）、PKCS#1 RSA（`BEGIN RSA PRIVATE KEY`）、SEC1 EC（`BEGIN EC PRIVATE KEY`）与 RFC 8410（`BEGIN ED25519/ED448 PRIVATE KEY`）；输出库内原始格式私钥字节（RSA=d、Ed25519=seed||pub、Ed448=seed、EC/SM2=scalar），并恢复对应公钥。
- **CSR 读取**（`csr::from_pem` / `from_der`）：解析 PKCS#10 `-----BEGIN CERTIFICATE REQUEST-----`，输出 subject、公钥、签名与 `tbs_raw`（可验签）。
- **`ed25519_derive_public_key` 公开 API**：从 32 字节 seed 派生 32 字节公钥（RFC 8032 §5.1.5），供 RFC 8410 私钥解析复用。
- **加密私钥 PEM 读取**（`private_key::from_pem_encrypted`）：支持 PBES2（RFC 8018）`-----BEGIN ENCRYPTED PRIVATE KEY-----`，实现 PBKDF2-HMAC-SHA256 + AES-128/256-CBC 解密（复用库内 `hmac_sha256` 与 AES 块 API），与 OpenSSL 生成样本互操作验证通过；错误密码正确拒绝。
- **CLI 增强**：`jpssl-cert info/verify/chain` 自动识别 DER 或 PEM 证书；新增 `jpssl-cert key --key <pem>`（查看私钥）与 `jpssl-cert csr --csr <pem>`（查看 CSR）子命令。

### Tests
- `test_ecdsa` 19 项、`test_tls` 156 项、`test_tls_socket` 37 项全部通过；
- P-256 求逆 20k 随机 + 边界对拍、4 线程 × 4 万并发 ECDH 压力无崩溃；
- 与 OpenSSL 双向互操作（P-256/384/521 签名、ECDH、RSA-PSS、国密套件）回归全部通过。
- `test_x509` 新增 54 条断言：PEM 证书往返（to_pem/from_pem）、Ed25519/Ed448/EC-P256/RSA 私钥 PEM 解析（含 PKCS#1 与 SEC1 传统格式，seed 与 OpenSSL 样本逐字节比对）、CSR 解析与签名验证（用 CSR 内公钥验签 `tbs_raw`）、加密 PEM（PBES2 AES-128/256-CBC，正确密码通过/错误密码拒绝）、X.509 version 语义回归（v3 编码为 `[0] INTEGER 2`、v1 无字段且 round-trip 字节一致）。
- 回归：`test_x509`（118 断言）、`test_base64` 全部通过；全套 30 个 CTest 通过。

> ⚠️ **该 UDP 数据报模式是自研简化封装，非标准协议，存在缺陷**：
> 报文格式与标准 `DTLS`（RFC 6347/9147）、`QUIC`（RFC 9000）不互通，
> 无法与 OpenSSL/Wireshark 等标准实现互操作；缺少 DTLS 的 cookie 抗 DoS、
> 握手分片/重传/乱序重组与防重放，UDP 丢包即握手失败。
> **标准 DTLS 1.2/1.3 已在本次发布提供（见上方 Added），建议新代码使用；
> QUIC 传输层 + HTTP/3 仍列入后续版本计划**。
> 注：QUIC 所需的 TLS 层支持已在本次发布提供（见上方 Added）。

## [0.9.14] — 2026-08-06

### Added
- **TLS socket 非阻塞模式**（`tls_connection` / `tls_listener`）：`set_nonblocking(bool)` 可在 `connect`/`listen` 之前调用（socket 创建时自动应用）；应用数据 `send()`/`recv()` 遇 `EAGAIN/EWOULDBLOCK` 时立即返回 `false` 并经 `would_block()` 判定，连接保持打开，配合 `wait_readable()`/`wait_writable()` 在事件循环中重试。握手阶段为有界等待（`set_handshake_timeout`，默认 30 秒），不永久阻塞。
- **非阻塞 TCP connect / accept**：connect 走 `EINPROGRESS` + poll 等待可写 + `SO_ERROR` 检查；listener 非阻塞时 `accept()` 无连接即返回 would-block（`wait_readable()` 配合），accept 出的连接 socket 继承监听器的非阻塞状态。
- **ALPN 协商（RFC 7301，扩展类型 0x0010）**：`tls_session` 新增 `alpn_protos`（客户端：按偏好序发送列表；服务端：本地支持列表）与 `alpn_selected`（协商结果）；客户端在 ClientHello 携带 ALPN 扩展，服务端按客户端偏好序选择后在 EncryptedExtensions 回传（服务端只选一个协议），客户端校验所选协议属于自己提议列表；配套 `tls_parse_alpn_list` / `tls_select_alpn` 工具函数。
- **协程 I/O（C++20 coroutine，零外部依赖）**：
  - `tls_co_task<T>` 泛型协程任务（热启动 + 对称转换，顶层任务由持有者析构清理）。
  - `tls_co_executor` 单线程 poll 驱动执行器（POSIX `poll` / Windows `select`），多个连接可共享；`run_once()` / `run()` 在 socket 就绪时恢复挂起协程。
  - `tls_connection::co_send()` / `co_recv()`：内部非阻塞 I/O，would-block 时挂起协程、可读/可写后由执行器恢复；`co_recv` 语义与 `recv()` 一致（合并多 record、跳过 NewSessionTicket）；与同步 `send()` / `recv()` 共用 rbuf_ 缓冲模型，续读无缝。
  - 使用前需 `set_nonblocking(true)` + `attach_co_executor(&ex)`。

### Fixed
- **`connect`/`server_handshake`/`accept` 不再清空会话预配置**：原 `session_ = tls_session{}` 会丢弃调用方预先设置的 ALPN 协议列表、签名方案（`sig_algs` / `sig_algs_cert`）与密钥交换组（`ks_group`），改为 `reset_session_preserving_config` 保留配置。
- **非阻塞 connect 识别 `EINPROGRESS`**：`is_would_block()` 的 POSIX 分支补充 `errno == EINPROGRESS`（此前只认 `EAGAIN/EWOULDBLOCK`），非阻塞 connect 在等待阶段不再被误判为失败。
- **协程发送/接收逐条加密**：`co_send` 先 `tls_encrypt`（自动分片）再写出；`co_recv` 走统一 rbuf_ 缓冲模型，mid-record would-block 续读不丢字节。

### Tests
- `test_tls_socket` 新增 21 条断言：ALPN（匹配/无交集/服务端未配置/客户端偏好序）、非阻塞（listener 非阻塞 accept 的 would-block、非阻塞 connect+握手、recv would-block、wait_readable 后重试、非阻塞继承）与协程回环（`co_send` / `co_recv` 双向交换 + 挂起-恢复），累计 37 条全部通过。
- 回归：`test_tls`（156 断言）、`test_tls_sm`（RFC 8998 全部）、`test_tls_large_msg`、`test_tls_stability` 全部通过。

## [0.9.13] — 2026-08-06

### Added
- **SM2 ECDH 公共接口**（`sm2_ecdh`，RFC 8998 / TLS 1.3）：对任意 SM2 公钥点做标量乘并输出 32 字节 X 坐标共享密钥；私钥校验 `0 < d < n`，公钥校验坐标范围与曲线方程（防无效曲线攻击），兼容 64 字节 `x||y` 与 65 字节 SEC1 `0x04||x||y` 输入。
- **TLS 1.3 curveSM2 key_share（RFC 8998 §3.3）**：SM 套件客户端在 `supported_groups` 广告 `curveSM2`(0x0029) 并发送 65 字节 SEC1 非压缩 key_share（同时保留 X25519 兜底临时对）；服务端在 SM 套件下优先选择 curveSM2 并在 ServerHello 回发自身 SM2 key_share；ECDHE 共享密钥（X 坐标）按标准 TLS 1.3 HKDF 派生命密钥。客户端/服务端解析均兼容 64 字节裸点格式的第三方实现。
- **RFC 8998 §3.2.1 SM2 ZA 合规**：TLS 1.3 CertificateVerify 的 SM2 签名/验签改用标识符 `"TLSv1.3+GM+Cipher+Suite"` 计算 ZA（`sign_scheme`/`verify_scheme` 新增可选 ZA 参数），与证书链签名使用的默认标识 `"1234567812345678"` 区分。

### Fixed
- **ClientHello key_share 线格式修正（RFC 8446 §4.2.8）**：`client_shares` 现在带 2 字节向量长度前缀（X25519/X448/SM2/PSK 路径统一修正），此前缺失向量长度、仅靠两端解析器自洽；修正后可与标准 TLS 1.3 实现互操作。
- **X448 ServerHello key_share 扩展长度修正**：扩展长度 60、扩展总长 70（此前写为 62/68，差 2）。

### Tests
- `test_sm` 新增 SM2 ECDH：双方共享密钥一致、64/65 字节输入等价、`ecdh(d,G) == X(d*G)` 已知答案、非法私钥/曲线外点/错误长度全部拒绝。
- `test_tls_sm` 新增线级断言：ClientHello 携带 curveSM2 组与 65 字节 key_share、ServerHello 回发 curveSM2、握手与记录层往返全部通过；`test_tls` 默认签名方案数量断言修正为 12（含 sm2_sm3）。
- 回归：`test_sm`、`test_tls_sm`、`test_tls`（136 断言）、`test_tls448`、`test_tls_large_msg`、`test_tls_stability`、`test_tls_socket`、`test_x509` 全部通过。

## [0.9.12] — 2026-08-06

### Added
- **SM2 域运算 ADX 汇编加速**：新增 `src/sm2_mont_asm_win.asm`（MSVC/MASM）与 `src/sm2_mont_asm.cpp`（GCC/Clang 内联汇编），4-limb 全展开 CIOS Montgomery 乘法，MULX (BMI2) + ADCX/ADOX 双进位链；运行时 CPUID 检测 BMI2+ADX 后由 `sm2.cpp` 自动分派，否则回退原 C 路径。实测 SM2 keygen/sign/verify 约 2.0–2.2×（约 105 µs/op，C 版约 194–232 µs）。

### Tests
- `test_sm` 新增 SM2 Montgomery asm 与可移植 CIOS 随机对拍：mod p / mod n 各 20000 组随机乘 + 边界值（0、1、m-1、m-2 等），汇编与参考实现完全一致且输出 < m；SM2 签名/验签与 TLS 国密套件（RFC 8998）回归全部通过。

## [0.9.11] — 2026-08-06

### Added
- **ECDSA P-521 (secp521r1)**：库 API `ecdsa_p521_keygen/sign/verify`（SHA-512，私钥 66 / 公钥 132 / 签名 132 字节），X.509 接入（`KeyType::ECDSA_P521`、OID secp521r1 / ecdsa-with-SHA512、SPKI 编解码、证书签名/验签/自签名），TLS 1.3 签名方案 `ecdsa_secp521r1_sha512` (0x0603) 端到端支持；`test_ecdsa` 新增 P-521 与 OpenSSL 双向交叉验证（公钥派生、双向签名互验、篡改检测）。
- **RSASSA-PSS 完整实现 (RFC 8017)**：`rsassa_pss_sign/verify` 升级为 RSA-2048/RSA-4096 × SHA-256/384/512，`saltLen` 默认 = hLen（RFC 8446），盐使用 CSPRNG；新增 `rsassa_pss_sign4096/verify4096` 与 `PssHash` 参数；TLS 1.3 CertificateVerify 统一复用该实现（删除原 tls.cpp 内重复的 PSS 代码）；新增 `test_rsa_pss`（2048/4096 × 三种哈希 × OpenSSL 双向互验 + 篡改检测）。

### Tests
- `test_ecdsa`（P-256/384/521）、`test_rsa_pss`、`test_tls`（136 断言）、`test_x509`、`test_ct`、`test_sm`、`test_tls_sm` 全部通过；ctest 40 项中 39 项通过（唯一失败为 `bench_hardware_accel` 的 AES-NI 计时断言，属本机虚拟化环境问题，与本次改动无关）。

## [0.9.10] — 2026-08-06

### Added
- **完整的 TLS `signature_algorithms` / `signature_algorithms_cert` 支持**（RFC 8446 §4.2.3、RFC 8998）：
  - 完整签名方案枚举：rsa_pkcs1_sha256/384/512、rsa_pss_rsae_sha256/384/512、ecdsa_secp256r1_sha256、ecdsa_secp384r1_sha384、ed25519、ed448、sm2_sm3。
  - `tls_session` 新增可配置的 `sig_algs` / `sig_algs_cert` 列表（空 = 全量默认），ClientHello（TLS 1.2/1.3/PSK）统一携带两个扩展，且 `signature_algorithms_cert` 自动裁剪为 `signature_algorithms` 的子集。
  - TLS 1.3 服务端按客户端偏好序协商 CertificateVerify 方案，拒绝未广告/与证书密钥类型不匹配/`rsa_pkcs1_*` 方案，并通过 `signature_algorithms_cert` 校验证书链签名算法；客户端同样强制校验对端方案与证书链签名算法。
  - TLS 1.2 ServerKeyExchange 签名方案按客户端列表协商（修复 `select_cipher_suite` 未映射 TLS 1.2 套件导致 ECDHE 分支从未启用的既有缺陷）。
  - CertificateVerify 按 RFC 8446 §4.4.3 使用上下文串（"TLS 1.3, server/client CertificateVerify" + 64×0x00 + Transcript-Hash）签名/验签。
  - 证书签名/验签重构为方案感知（`sign_scheme` / `verify_scheme`）：新增 RSA-PSS（SHA-256/384/512，saltLen=hLen）、RSA-PKCS1 SHA-384/512、ECDSA P-384 支持。
- **X.509 ECDSA P-384**：`KeyType::ECDSA_P384`（OID secp384r1 / ecdsa-with-SHA384），编码/解析/自签名/链验证与 `tls_make_x509_self_signed` 集成。
- **测试**：`test_tls` 新增 56 条断言（扩展内容、P-384/RSA-PSS/Ed448 握手、未广告方案拒绝、`signature_algorithms_cert` 强制、线级 RFC 8446 上下文校验、TLS 1.2 SKX 协商），累计 136 条全部通过；socket/stability/large_msg/x509/ecdsa/sm 测试全部通过。

### Fixed
- `src/aes_ccm.cpp` 的 `#ifdef __x86_64__` 守卫在 MSVC 下未生效（MSVC 定义 `_M_X64`），导致 Windows 构建失败；改为 `__x86_64__ || _M_X64`（与 `sha256_sha_ni.cpp` 既有修复一致）。

## [0.9.9] — 2026-08-05

### Added
- **GHASH / GF(2^128) 公共接口**：`include/aes.hpp` 新增增量 GHASH（`ghash_ctx` / `ghash_init` / `ghash_update` / `ghash_final`，流式分块、末尾补零）与完整 GCM 认证哈希 `gcm_ghash(H, aad, data, out)`（含 AAD/密文分段补零与长度块，输出 GCM 的 S 值）；`gf128_mul`（PCLMULQDQ 加速）与一次性 `ghash` 保持公开。README 增加用法说明与算法总览行。

## [0.9.8] — 2026-08-05

### Added
- **密码套件基准重构**（`bench_cipher_suites`）：预热 + 自适应迭代 + 多轮取最小（消除频率波动）；jpssl/OpenSSL 输出缓冲均预分配，计时区间无堆分配；默认按 TLS 记录尺寸（16 KiB）分片并逐记录派生 nonce（`base_iv ^ seq`），贴近真实 TLS 记录层，`--record 0` 可退化为整块吞吐；新增 `--data-mb / --record / --rounds / --target-ms / --no-ossl` 参数和统一汇总表（GB/s + 对比倍率）。

### Fixed
- **AES-GCM GHASH 致命性能 bug**：`aes_gcm_avx2/avx512.cpp` 的 `gcm_ghash_core` 号称 PCLMULQDQ 路径，实际每块把数据落回内存并调用逐位软件 `gf128_mul`（约 85 ns/块），AES-128-GCM 吞吐仅 0.012 GB/s。已改为寄存器内 PCLMULQDQ 乘法 + 4/8 路并行 GHASH（H^1..H^4 / H^1..H^8），并启用 `aes_cpu.cpp` 中被禁用的 PCLMUL 快路径（`gf128_mul` / `ghash`）。
- **PCLMUL GHASH 正确性**：旧死代码 `gcm_gf128_mul` 的模约简漏掉乘积高 64 位（x^192..x^255），`aes_cpu.cpp` 的版本也有 64 位 lane 顺序错误；已按数学推导重写完整约减，并用 20 万随机输入 + OpenSSL 交叉验证（128/192/256 位、0..65536 字节、含 AAD）。
- **GHASH 字节序转换**：NIST bit-reflected 字节序到 PCLMUL 自然域的映射是逐字节位反转（且高低半字节位置互换），原实现误用整块 bswap；三处 `gf128_bitrev/gcm_bitrev` 统一修正。
- **GCM 部分块越界读写**：AVX2/AVX512 GCM 的 4/8 路批量循环把含部分块的最后一组当整组处理（读越界、写脏字节、GHASH 错误），现只对完整 64/128 字节组走批量路径，其余交尾部逐块处理。
- **AVX2/AVX512 GCM 支持 192/256 位密钥**：去掉仅限 AES-128 的守卫（4/8 路 AES-NI + PCLMUL GHASH 与密钥长度无关）。
- **VAES GCM 后端**（`src/aes_gcm_vaes.cpp`）：新增 256-bit VAES（VEX.256）加速的 4 块并行 AES-GCM。Alder Lake / Raptor Lake 等 CPU 熔断 AVX512 但仍支持 256-bit VAES + VPCLMULQDQ，该后端让这类机器无需 AVX512 即可使用向量化 AES（每条 vaesenc 处理 2 块 vs AES-NI 1 块）；`aes_gcm_*_auto` 分派优先级改为 AVX512(8路) > VAES-256(4路) > AVX2 > 软件，`bench_hardware_accel` 增加 VAES 路径行。VAES 指令用内联汇编（GCC/Clang `-mvaes`），避免 `-mavx512vl` 令编译器输出 AVX512 指令在无 AVX512 CPU 上 SIGILL（实测 `vpternlogq` 即触发）。
- **GHASH 改用 256-bit VPCLMULQDQ**（VAES 后端）：4 路并行 GHASH 的四个域乘积打包成两组 2-lane 乘法，一条 `vpclmulqdq ymm` 同时算两个独立的 128-bit 无进位乘法（GCC 的 `_mm256_clmulepi64_epi128` 同样被 `-mavx512vl` 守卫，用内联汇编 + 逐 lane permute/mask 移位实现）；独立微基准 4-way GHASH 快约 1.5x，整条 VAES-GCM 在高频干净测量下比 AVX2 路径快约 16–21%（本机频率波动较大，节流场景下持平）。
- **AES-CCM 性能优化**（`src/aes_ccm.cpp`）：CTR keystream 改为 4 路并行 AES-NI（4 个计数器块同时加密），解密/加密 XOR 用 128-bit 向量；CBC-MAC 链与 CTR 融合为单遍遍历（读明文 → 串行 MAC + 向量 XOR），不再构建 16MB 的 `mac_input`/`keystream` 中间缓冲；MAC 状态全程留寄存器。计数器对 q ≤ 4（TLS 场景 q=2/3）用 bswap + 大端加法快速递增，q > 4 走通用路径。
- **TLS 记录层 GCM 改用自动分派 + 减少拷贝**：`src/tls.cpp` 的 10 处 `aes_gcm_encrypt/decrypt`（非分派软件路径，~0.25 GB/s）全部改为 `aes_gcm_encrypt/decrypt_auto`，TLS 记录层从此走 VAES 加速路径；`tls_encrypt` 预预留输出容量、`tls_encrypt_record` 直接追加到输出（去掉中间 record 向量）、`tls_decrypt` 预留合并容量。实测 TLS 1.3 AES-128-GCM 记录加密从约 0.53 → 0.80 GB/s（相对最初软件路径约 3 倍），单条 16 KiB 记录的封装开销从约 10.6µs 降到约 2.8µs。
- **GCM 就地（in-place）接口 + TLS 记录层零拷贝加密**：新增 `aes_gcm_encrypt/decrypt_inplace`（AVX2/VAES/AVX512 三后端重构为指针输出核心，自动分派；软件回退用临时向量保证正确性），密文直接写回输入缓冲，无中间向量；TLS 1.3/1.2 GCM 记录加密改为直接在输出缓冲中构建记录（头部 + inner 帧 + 标签占位）后就地加密，每记录只剩 1 次明文拷贝（记录缓冲写入本身不可避免）。实测 TLS 1.3 AES-128-GCM 记录加密约 1.7 GB/s（较 0.80 再翻倍，稳定频率下），单条 16 KiB 记录封装开销降至约 0.7–1.1µs，基本达到 GCM 单记录调用的极限；解密侧因输入为 const 指针（需合并到输出），保留原有路径。
- **全组件零拷贝接口收进内部头文件**（`src/cipher_inplace.hpp`，不随库安装）：AES-GCM、AES-CCM、ChaCha20-Poly1305、SM4-GCM、SM4-CCM 均新增 `*_inplace` 就地加解密（密文/明文直接写回输入缓冲）；公共头文件 `include/*.hpp` 只保留非零拷贝的 vector/span API（从 `aes.hpp` 移除就地声明），零拷贝接口仅供 TLS 记录层使用。TLS 1.3 记录层的 GCM/CCM/ChaCha/SM4-GCM 与 TLS 1.2 的 GCM/ChaCha 加密全部走就地路径。
- **修复 SM4-CCM 标签 bug**：`sm4_ccm_encrypt` 原实现 tag 直接取 `E(ctr0)`，漏异或 CBC-MAC，与其自身解密（及 NIST SP 800-38C 标准）的验证公式不一致；已改为 `tag = E(ctr0) ^ MAC`。另修复就地解密中 MAC 加密块计数器残留问题（`|= 0x01` 后 `&= 0x07` 清不掉 counter 位）。
- **测试修复连锁效应**：`test_aes_modes` 从 1200 过 36 挂 → 1236 全过；`test_aes` 100 全过（此前 1 挂）；TLS/AES 相关测试全部通过。

### Performance
- AES-128-GCM（AVX2，16 MiB、16 KiB 记录）：加密 0.012 → 约 3.8 GB/s（~300x），解密约 7 GB/s（反超 OpenSSL ~1.6x）；整块模式约 2.7 GB/s。
- AES-256-GCM：加密约 2.3 GB/s、解密约 3.9 GB/s（原 0.01 GB/s，~200x 提升，解密反超 OpenSSL ~1.3x）。
- 软件/AES-NI GCM 路径（无 AVX2 机器、含 AAD 场景）：PCLMUL GHASH 启用后同样大幅提速。
- 说明：Raptor Lake 上 AES-NI 与 256-bit VAES 的 AES 吞吐均为 2 块/周期；配合 256-bit VPCLMULQDQ GHASH 后，VAES 路径本机实测比 AVX2 路径快约 16–21%（AES-128/256-GCM 加密约 3.8–4.2 GB/s），瓶颈从 GHASH 转移回 AES。VAES 后端在 Ice Lake+ / Zen 4 等平台收益更大。
- AES-128-CCM / CCM-8（16 KiB 记录）：加密 0.49 → 1.9–2.4 GB/s（约 4x，与 OpenSSL 持平），解密 0.52 → 1.9–2.4 GB/s（反超 OpenSSL 1.16–1.46x）；剩余上限是 CBC-MAC 串行链（每块一轮 AES 的固有延迟）。
- TLS 1.3 AES-128-GCM 记录层（64 MiB 大消息）：加密 0.25 → 0.80 GB/s（软件路径 → VAES + 记录层减拷贝）；剩余差距来自 16 KiB 记录粒度下每记录的封装/拷贝（约 3 次 16KB 数据搬移）与 GCM 单记录调用开销，若需进一步追平需给 AEAD 增加“输出到既有缓冲”接口以消除中间拷贝。
- TLS 1.3 AES-128-GCM 记录层（续）：就地加密落地后 0.80 → 约 1.7 GB/s（记录层开销 ≈ GCM 单记录调用上限），加解密合计约 0.5–0.9 GB/s（受频率影响；解密受 const 输入限制，需一次合并拷贝）。

## [0.9.7] — 2026-08-05

### Added
- **Ed25519 真·批量验证**：`ed25519_batch_verify` 由“逐条循环”改为随机盲化的多标量乘法——全部签名共享同一条 4-bit 窗口倍点链（每窗口只做一次部分加），各点预计算表用一次批量求逆完成仿射化，并用每签名 128 位随机因子盲化防伪造放大。标量批量大小由 1 提升到 128 条/块，`ed25519_batch_size()` 相应返回 128。
  - 实测（i7-13700K, GCC -O2）：256 条签名批量验证约 10.5–12 ms（旧实现约 25.6 ms，提速约 2.2–2.4x；对 OpenSSL 逐条循环约 2.3–2.6x）；单签名摊销约 41–47 µs（单条 `ed25519_verify` 约 100 µs）。
  - 语义不变：全部有效返回 true，任一签名无效（含 s ≥ l、公钥/签名解压失败）返回 false；随机源不可用时自动退化为逐条验证。
- **Ed25519 内部复用**：`ed25519_body.inc` 公共 API 段增加 `JPSSL_ED25519_NO_PUBLIC_API` 裁剪开关，批量后端可直接复用 r51 点运算，避免链接期重复符号。

### Fixed
- **`sc_negate` 借位链错误**：`borrow = (__uint128_t)L64[i] - a[i] - borrow; borrow >>= 64` 在 128 位无符号减法下溢时高字为 `2^64-1` 而非 `1`，导致 `l − a mod l` 高位肢体整体错乱。该函数此前为死代码，批量验证启用后暴露；已改为 `d = L64[i] − a[i] − borrow; borrow = (d > L64[i])` 的标准写法。

### Changed
- `ed25519_batch_dispatch` 不再区分 AVX512 分支：多标量批验证对指令集不敏感，所有机器统一走 CPU 批量后端（AVX512 后端函数保留以兼容 API）。

## [0.9.6] — 2026-08-05

### Added
- **SHA-1 支持**：新增 `include/sha1.hpp` / `src/sha1.cpp`（标量，FIPS 180-4，`sha1_ctx` 增量接口 + `sha1_hex` + 一次性 `sha1`）；`sha1_batch` 对等长消息按 AVX-512（16 路）> AVX2（8 路）> 标量自动分派。
- **SHA-1 SIMD 多缓冲**：`src/sha1_avx2.cpp`（8 路并行，YMM 每 lane 一条消息，W 调度与 80 轮全向量化）与 `src/sha1_avx512.cpp`（16 路并行，ZMM），无需跨 lane 洗牌，结构一致；实测 8×4KiB 批量哈希约 2147 MiB/s（vs 标量 597 MiB/s，约 3.6x，MSVC Release，AVX2）。
- **SHA-1 测试**：`tests/test_sha1.cpp`（NIST/FIPS 向量、100 万 'a'、边界长度 0/55/56/57/63/64/65/119-129、增量/逐字节更新、AVX2/AVX512 与标量交叉验证、batch 分派 1-20 条消息、OpenSSL 对比）。
- **jpssl-crypt 支持 `hash --algo sha1`**；CLI 暴露 base64：新增 `b64encode` / `b64decode` 子命令（RFC 4648，解码容忍空白字符）。

## [0.9.5] — 2026-08-05

### Added
- **Base64 AVX2 / AVX-512 加速**：`src/base64_avx2.cpp`（24B→32B/迭代）与 `src/base64_avx512.cpp`（48B→64B/迭代），采用 pshufb 查表 + 乘法解包的经典 SIMD 方案；`base64_encode`/`base64_decode` 运行时按 AVX-512（含 BW）> AVX2 > 标量自动分派，尾部与 `=` 填充仍走标量，语义与原有 API 完全一致。
- **CPU 特性检测**：`cpu_features.hpp` 新增 `cpu_has_avx512bw()`。
- **测试与基准**：新增 `tests/test_base64.cpp`（RFC 4648 向量、全长度随机往返、SIMD 直接交叉验证、非法输入，484 断言）与 `benchmarks/bench_base64.cpp`（标量/AVX2/AVX512/自动分发对比）。

### Changed
- CMake 注册 `src/base64_avx2.cpp` / `src/base64_avx512.cpp`，按源文件设置 `/arch:AVX2`、`/arch:AVX512`（MSVC）或 `-mavx2`、`-mavx512f -mavx512bw`（GCC/Clang）。

## [0.9.4] — 2026-08-05

### Added
- **国密证书透明（SM2 CT）**：新增 `include/ct.hpp` / `src/ct.cpp`，基于 RFC 6962 框架、以 SM2/SM3 替代 ECDSA/SHA-256（参考 GM/T《证书透明规范》草案）：
  - SM3 默克尔树：根哈希 / 审计路径 / 一致性证明（验证按 RFC 9162 §2.1.4.2）；
  - SM2 标准签名（GB/T 32918，默认 ID `1234567812345678` 计算 ZA）；
  - PreCert / MerkleTreeLeaf / SCT / STH 的 TLS 风格编解码；
  - X.509 集成：LogID、precert poison / SCT list 扩展、`finalize_precert`；
  - 内存日志 `sm2_ct_log`：add-pre-chain / add-chain / get-sth / get-proof-by-hash / get-entries / get-sth-consistency。
- **RFC 4648 base64**：新增 `include/base64.hpp` / `src/base64.cpp` 及单元测试。
- **X.509 原始扩展保留**：`x509_cert` 新增 `raw_extensions`，未知扩展在解析/编码时原样保留（CT 的 SCT list / poison 扩展依赖此能力）。
- **TLS socket 封装层**：新增 `include/tls_socket.hpp` / `src/tls_socket.cpp`，在消息级 TLS API 之上提供跨平台（Windows Winsock / Linux POSIX）的 `tls_connection` 与 `tls_listener`：TCP 连接管理、TLS 1.3 客户端/服务端完整握手、record 收发（自动处理半包/粘包）、应用数据加密收发；新增回环测试 `tests/test_tls_socket.cpp`。
- **国际标准 CT（RFC 6962）**：`ct_log` 通用日志类同时支持国密（SM3+SM2）与国际（SHA-256 + ECDSA P-256）算法；新增 `sha256_leaf_hash`/`sha256_node_hash`、SHA-256 默克尔树（根/审计路径/一致性证明，`CtHashAlg` 参数）、`issue_sct_std`/`verify_sct_std`/`sign_sth_std`/`verify_sth_std`、`compute_log_id_std`；`sm2_ct_log` 保留为兼容别名。
- **RFC 6962 RSA CT**：新增 `issue_sct_rsa`/`verify_sct_rsa`/`sign_sth_rsa`/`verify_sth_rsa`（SHA-256 + RSA-2048 PKCS#1 v1.5，signature_algorithm=rsa）；`ct_log` 新增 RSA 构造函数（`ct_log(rsa_crt_key, rsa_public_key)`），LogID = SHA-256(RSA SPKI)。
- **HTTPS + CT 示例**：新增 `examples/https/`（`https_server` + `https_client`）——服务器内嵌国际 CT 日志、签发带 SCT 的 ECDSA 证书并提供 `/`、`/ct/cert`、`/ct/precert`、`/ct/ca`、`/ct/log-key`、`/ct/sth`、`/ct/proof` 端点；客户端完成证书链校验、SCT/STH 签名校验与包含性证明审计。

### Fixed
- **一致性证明验证条件错误**：`verify_consistency` 的分支条件误写为 `fn == 0 || (fn & 1)`，应为 RFC 9162 §2.1.4.2 的 `(fn & 1) || fn == sn`，导致除少数组合外一致性证明全部验证失败；已修复，全部 (first, second) 组合通过。
- **`tls13_make_new_session_ticket` 栈溢出**：`rand32` 固定写入 32 字节，原代码写入 4 字节局部变量（MSVC C4789 已静态证明溢出），改为 32 字节缓冲取前 4 字节；修复 test_tls / test_tls_sm / test_tls448 在 Release 下的段错误。
- **`rsa_bignum::from_bytes` 越界写**：无长度边界检查，RSA-4096 路径传入 512 字节会写穿 256 字节的 `rsa_bignum`，现按类型容量钳制长度。
- **`encode_tlv` / `encode_bit_string` 空指针 UB**：空数据时对 `nullptr` 做 `+0` 指针运算，增加长度守卫。
- **SHA-NI 实现 MSVC 下未编译**：`sha256_sha_ni.cpp` 整体被 `#ifdef __x86_64__` 保护，而 MSVC 不定义该宏，导致静态库缺失 `sha256_sha_ni` 符号（bench_hardware_accel 链接失败）；改为 `__x86_64__ || _M_X64`。
- **`from_der` BasicConstraints 解析偏移错误**：解析 SEQUENCE 后未重置偏移，导致 CA 证书从 DER 解析后 `is_ca()` 恒为 false（证书链验证报 "root not CA"）；已修正。

### Changed
- CMake 注册 `src/base64.cpp` / `src/ct.cpp` 及 `tests/test_ct.cpp`（CTest 33/33 全部通过）。
- README 补充国密 CT 能力与缺陷修复说明。

## [0.9.3] — 2026-08-04

### Added

#### Windows (MSVC) 平台支持
- **128 位整数兼容层** `include/jpssl_platform.hpp`：MSVC x64 无 GCC 的 `__uint128_t`，通过 `/FI` 强制包含该头，以 `jp_uint128` 类 + `#define __uint128_t jp_uint128` 提供等价语义（基于 `_umul128`/`_addcarry_u64`/`_subborrow_u64`/`_udiv128`，全部内联）。业务代码零改动；GCC/Clang 继续使用原生类型。
- **系统随机源** `include/rand_os.hpp` + `src/rand_os.cpp`：统一 `jpssl::os_rand_bytes`——Windows 用 `BCryptGenRandom`，Linux 用 `/dev/urandom`；`rsa.cpp`/`tls.cpp`/`ecdsa.cpp`/`sm2.cpp`/`jpssl_crypt` 全部接入（MSVC 的 `std::random_device` 是确定性的，不再用于密钥/签名 nonce）。
- **CPU 特性检测 MSVC 实现**：`cpu_features.hpp` 改用 `__cpuidex`/`_xgetbv`（含 OSXSAVE/XCR0 检查），AES-NI/AVX2/AVX512/SHA-NI 运行时分派在 Windows 同样生效。
- **CMake 平台分支**：MSVC 编译选项（`/utf-8`、`/bigobj`、`/EHsc`、`/FI`、`NOMINMAX`）、按源文件加 `/arch:AVX2|AVX512`、bcrypt 链接、`WINDOWS_EXPORT_ALL_SYMBOLS` DLL 导出、Windows 下静态库改名 `jpssl_cpu_static.lib`（避免与共享库导入库同名冲突）、MUSA 自动禁用、OpenSSL 改为可选（缺失时跳过对比测试）。
- **测试/基准条件化**：OpenSSL 依赖的测试目标在无 OpenSSL 时整体跳过。
- README 新增「Windows 构建（MSVC）」章节。
- README：性能基准章节补全 `bench_sm4` / `bench_ed25519_ossl` / `bench_ed448_x448_ossl` / `bench_x25519_ossl` 目标并说明 GPU 段由 `JP_MUSA` 守卫（MUSA 关闭时自动跳过、基准仍可编译运行）；条件编译章节补充 `JP_ENABLE_BENCH`（默认 OFF）与 `JP_ENABLE_OPENMP`（默认 ON）选项。

### Fixed
- **`jp_uint128::operator&=` 高位未清零**：64 位掩码与 128 位值按位与时 `hi` 残留，导致 radix-2^51 域运算（fe51_mul 进位链）在大输入下错误——表现为 X25519 密钥协商结果错误；已改为 `hi = 0`（与 GCC 原生 `__uint128_t` 语义一致）。
- **`_umul128` 参数顺序错误**：低 64 位返回值被误作高 64 位，导致 128 位乘法 lo/hi 颠倒（RSA Miller-Rabin 误判、密钥生成死循环）；已修正。
- **RSA 2048 密钥生成死循环（跨平台既有 bug）**：`keygen_fn_32` 找素数时清除 bit62，使 p/q 被限制在 `[2^1023, 1.25·2^1023)`，n = p·q 恒为 2047 位，`n.bit_length() < 2048` 重试循环永不退出；移除 bit62 清除（与 `find_prime` 一致）。
- **`keygen_with_watchdog` 超时适配**：Windows 上 jp_uint128 模拟层慢约一个数量级，300ms/3s 的 Linux 超时必然触发 abort 重试并失败，超时放大 20 倍。
- **`keygen_with_watchdog` 偶发锁死（跨平台既有 bug）**：原实现用 `std::thread` + `condition_variable` + `join()` 看门狗，在 Windows 上偶发 CPU≈0% 阻塞（watchdog 线程与 `work()`/`join()` 时序竞争）；且 `rsa_keygen_crt`/`rsa4096_keygen_crt` 的 `while (n.bit_length() < ...)` 重试循环不检查 abort，`find_prime` 因超时提前返回后 p/q 不变、重试永不达标而**死循环**。已重构为 deadline 时间预算（`find_prime` 每步检查 `steady_clock` 超时，超时置 `g_kgen_abort` 并返回），彻底移除看门狗线程；并在重试循环条件中加入 abort 检查。验证：2048/4096 CRT keygen 各 10/3 次全部快速完成且加解密往返正确。
- **GCC 扩展 → 标准 C++**：`tls.cpp` 两处 VLA（`uint8_t buf[n+size()]`）改 `std::vector`；`tests/test_aes.cpp`、`test_ghash.cpp`、`test_ossl_verify.cpp` 零长度数组 `[0]` 改 `[1]`。
- **`timegm` 平台化**：`x509.cpp` 在 Windows 用 `_mkgmtime`。
- **MUSA GPU 测试守卫（含 benchmarks）**：`src/main.cpp` 的 5 个 GPU 测试函数、`tests/test_openssl_compare.cpp` 的 GPU 基准，以及 `benchmarks/bench_sha512.cpp` / `benchmarks/bench_hardware_accel.cpp` 的 GPU 段（`musa_sha512_init/cleanup/compute/batch`、`musa_chacha20_pool_*`）均加 `#ifdef JP_MUSA` 守卫，MUSA 关闭时跳过对应 GPU 代码；修复 `JP_ENABLE_MUSA=OFF` 下 `bench_sha512`、`bench_hardware_accel` 的 MUSA 未定义引用而链接失败的跨平台既有缺陷；CMake MUSA 分支为 `jpssl-test`、`bench_sha512`、`bench_hardware_accel` 补 `JP_MUSA` 宏定义。
- **X.509 证书验证修复（跨平台既有 bug，`test_x509` 从 53/54 修复到 54/54 全过）**：
  - `verify_signature` 改用 `from_der` 保存的原始 `tbs_raw`（与签名时字节一致），消除 `to_der()` 重编码导致的 TBS 差异（此前 DER 往返证书签名验证失败，影响 `test_x509` 的 TLS 自签名项与 `test_tls_sm` 握手）。
  - `encode_spki` 的 ECDSA/SM2 公钥从错误的 `OCTET STRING` 改为标准的 `BIT STRING`（此前 `from_der` 因要求 BIT STRING 而解析失败）。
  - `tlv_to_oid` 修复两处 OID 编码错误：多字节组件缺失 base128 延续位（0x80）、首字节被拆分为 `[a,b]` 而非保留 DER 合并格式 `40*a+b`——导致 SM2/多字节 OID 的 key_type 与签名算法解析失败。
- **SM 套件 TLS 1.3 握手修复（跨平台既有 bug，`test_tls_sm` 全过）**：`tls13_make_server_flight` 在解析 ClientHello 的 cipher_suite（选择 `TLS_SM4_GCM_SM3`）**之前**就更新 CH transcript，导致 Server 端 transcript 用默认套件的 SHA-256 初始化，而 Client 端（显式设置 SM 套件）用 SM3 —— 两端 transcript 哈希算法不一致，握手密钥不同，`tls13_process_server_flight` 解密第一个加密记录失败。修复：把 CH 的 transcript 更新移到 cipher_suite 解析之后，两端 transcript 均为 SM3。此前 X25519 握手未受影响（默认套件恰好同为 SHA-256）。
- **RSA 性能优化（MSVC）**：`mont_mul`（RSA 运算最大热点，rsa_body.inc）在 MSVC 下用手写 `_umul128`/`_addcarry_u64` intrinsic 序列替代 jp_uint128 表达式的 `operator*`/`operator+` 链。MSVC x64 ABI 中大于 8 字节的结构体通过隐藏指针按栈返回（非 RDX:RAX 寄存器对），三次内层循环（乘加 a×b、Montgomery 归约 u×m、进位传播）每轮产生大量临时对象和栈分配，导致 RSA 密钥生成与签名偶发 CPU 几乎阻塞。手写 intrinsic 路径完全消除临时对象，RSA 运算恢复 100% CPU 利用率，关键路径加速显著。
- **RSA 卡死根因修复（MSVC 优化引入的回归）**：
  - `mont_mul` 优化分支的 `_umul128` 参数颠倒（`hi=_umul128(...,&lo)`：返回值是低 64 位、指针输出高 64 位）→ Montgomery 数学完全错误 → `bn_is_prime` 对素数候选卡死（`bn_modpow(2,153,613)` 曾 150s 不返回）→ `rsa_keygen` >97s → `test_tls` 卡在 RSA 证书测试。已改为 `lo=_umul128(...,&hi)`；另修复进位链 ca 权重与 cf1/cf2 双进位传播。
  - `bn_modinv` 重写：原除法版欧几里得 or_/rc 角色颠倒（除法方向反、0.00s 返回错误结果），二进制扩展欧几里得又要求模数 m 为奇数（RSA 的 phi=(p-1)(q-1) 为偶数，÷2 需 2 可逆故失效）→ 改为标准扩展欧几里得除法版（r0=m,r1=a，系数 `(s0-q·s1) mod m` 经 `bn_mulmod` 取模更新，无 BN 容器截断、对任意 m 有效）。修复后 RSA 2048 往返 sign/verify 全部正确。

### Changed
#### SM3 标量汇编 (Windows x64, MASM)
- 新增 `src/sm3_win.asm`：`sm3_compress_asm` 标量压缩函数，64 轮全展开、状态 A–H 寄存器轮换、W[0..67] 栈上展开、block 大端 bswap 载入；MSVC x64 下 `sm3_cf` 自动走汇编（`JP_HAVE_SM3_ASM`），其他平台回退 C 标量。
- 实测（本机 MSVC Release）：8 KiB 单条 SM3 吞吐约 350 → 387 MB/s（约 +10.5%），对比 OpenSSL 4.0 的 349 MB/s 约 +11%；纯标量指令，不依赖 BMI2/ADX，任意 x86-64 CPU 可用。

#### RSA 性能优化（OpenSSL FIOS 移植 + keygen 兜底）
- **RSA Montgomery 乘法移植 OpenSSL FIOS**：`src/rsa_mont_asm.cpp`/`src/rsa_mont_asm_win.asm` 实现 4 路展开 ADCX/ADOX 的 FIOS Montgomery 乘法，Windows 走手写 MASM（MULX 加速，K=32/64），Linux 走 GCC 内联汇编；加密/解密/批量运算全部接入。运行时不支持 BMI2/ADX 的 CPU 自动回退到标量 `_umul128` 实现，CPUID 检测结果进程内缓存。
- **CRT 半尺寸汇编加速**：CRT 私钥解密的 p/q 模幂改用半尺寸 Montgomery 乘法 `mont_mul_half_`（只处理前 K/2 个 limb），MASM 宏生成双实例 + GCC 动态 HK 单实例，核心吞吐提升约 1.3–1.45×。
- **CRT 解密默认双线程 OpenMP**：`rsa_decrypt`/`rsa_crt_decrypt` 的两路独立模幂 m1/m2 用 `#pragma omp parallel sections num_threads(2)` 并行（`-DJP_ENABLE_OPENMP=OFF` 或非 OpenMP 编译器自动回退串行），2048/4096 解密实测提速 1.5–1.7×。
- **RSA keygen 素数预算兜底**：素数搜索预算 100ms（2048/4096 keygen 统一），超时即从预制素数表（`src/rsa_prebuilt_primes_data.inc`，1024 位×50 对 + 2048 位×50 对，MR 已验证）随机取一组完成 keygen，保证 keygen 永不因素数搜索卡死；预制素数公开、仅作测试/兜底，不用于生产密钥。

#### Ed25519 性能优化
- 新增 `src/fe51_mul_adx.asm`：radix-2^51 域乘法/平方走 ADX 指令集汇编快速路径；对比 OpenSSL keygen 9.4× / sign 8× / verify 4.3×，全面反超。
- 新增 OpenSSL 对比基准 `benchmarks/bench_ed25519_ossl.cpp`。

#### X25519 性能优化
- 新增 `src/fe51_sq_adx.asm`：域平方专用 ADX 汇编（15 次 MULX 利用对称性，非对角项翻倍），`fe51_sq` 运行时按 BMI2+ADX 分派。
- 梯形改用无进位减法 `ladder_sub`（输出 limb < 2^53 直接作 mul/sq 输入），并将 AA 平方原地化消除每轮一次 `fe51_copy`。
- 实测（Raptor Lake，无 AVX512）：X25519 标量乘 47.0µs → 39.6µs（+15.8%），ECDH 吞吐 1.15× OpenSSL EVP derive 路径；RFC 7748 向量、30 万组随机域运算、6000+ 组 OpenSSL 对拍全部通过。

#### Poly1305 AVX2 向量化
- 新增 `src/poly1305_avx2.cpp`（4 块并行，26-bit 肢体），`chacha20_poly1305` 运行时分派接入。

#### Ed448 / X448 性能优化与 SIMD 向量化
- 字段运算改用 u64 原语 + 专用平方 + 窗口化求逆，标量 mod-L 折叠，修复加法/倍点/乘法进位 bug；对比 OpenSSL：keygen 5.7× / sign 6× / verify 2.3× / x448 1.9×，新增基准 `benchmarks/bench_ed448_x448_ossl.cpp`。
- 新增 radix-2^28 的 4/8 路 SIMD 字段层 `src/fe_448_simd.hpp`，向量化批量验签与 X448 批量阶梯；新增 `x448_scalar_mult_batch` API（AVX512=8 路 / AVX2=4 路 / 标量回退）及测试 `tests/test_x448_batch.cpp`，X448 每签提速约 24%。

#### SM2 / SM3 性能优化
- **SM2 重写**（`src/sm2.cpp`）：域运算改为 Montgomery（R=2^256）4×64 位表示，CIOS 乘法 + 对称平方（10 次 MULX），MSVC 用 `_umul128/_addcarry_u64` intrinsic；求逆用 Montgomery 快速幂并支持批量仿射化（单次求逆）；标量乘改用宽度-5 wNAF（G 奇倍点表全局预计算，仿射混合加法），验签用 Shamir 双标量同时乘共享倍点；顺带修正 e/x1 规约、坐标规约与签名格式细节。实测（MSVC Release）：keygen 16.2ms → 0.19ms（约 84×）、sign 18.0ms → 0.22ms（约 83×）、verify 30.6ms → 0.23ms（约 135×）；对比 OpenSSL 4.0：keygen 1.31× / sign 1.35× / verify 1.26×，双向签名互操作（OpenSSL 验 jpssl、jpssl 验 OpenSSL）全部通过。
- **SM3 标量重写**（`src/sm3.cpp`）：压缩函数按 8 轮一组展开，T/FF/GG 全部编译期常量消除分支，W′ = W_j ^ W_{j+4} 轮内即时计算；8 KiB 块吞吐约 349–356 MB/s，与 OpenSSL 持平。
- 新增 OpenSSL 对比基准 `benchmarks/bench_sm_ossl.cpp`（SM3 吞吐 + SM2 keygen/sign/verify，含 DER↔原始 r||s 签名互操作自检）。

### 验证
- 本机 VS 2026 Build Tools（MSVC 19.51）+ CMake/Ninja 全量构建通过（166 目标，含静态/动态库、3 个命令行工具、38 个测试 exe）。
- CTest 21 项中 19 项通过：AES/CCM/GCM、SHA-3/SHA-512、TLS 1.2/1.3 全握手与 0-RTT、X.509 DER/证书链、Ed25519/Ed448 RFC 向量、X25519/X448 RFC 向量、SM4-GCM、RSA 2048 keygen/sign/verify、OpenSSL 对比。
- 已知遗留（Linux 同样存在，非 Windows 特有）：`x509_cert::verify_signature` 对 DER 重新编码证书的验证（`test_x509.cpp` 已有 TODO 注释），影响 `test_x509` 的 TLS 自签名项与 `test_tls_sm` 的握手项。

---

## [0.9.2] — 2026-08-01

### Added

#### ChaCha20 AVX2/AVX512 硬件加速
- 新增 `src/chacha20_avx2.cpp`（181 行）与 `src/chacha20_avx512.cpp`（134 行）：ChaCha20 keystream 的 AVX2/AVX512 并行路径
- `src/chacha20_poly1305.cpp` 与 `include/chacha20_poly1305.hpp` 增加硬件加速分派入口，`CMakeLists.txt` 增加对应编译目标

#### RSA 填充方案与原语
- 新增 `src/rsa_oaep.cpp`（156 行）：RSA-OAEP 加密填充
- 新增 `src/rsa_pss.cpp`（160 行）：RSA-PSS 签名填充
- 新增 `src/rsa_schemes.cpp`（131 行）与 `src/rsa_prim.cpp`（327 行）：RSA 方案层与底层模幂/素数原语
- `include/rsa.hpp`、`src/rsa_body.inc` 相应扩展公开 API

#### RSA 基准测试
- 新增 `benchmarks/bench_rsa_cpu_gpu.cpp`（320 行）：RSA 2048/4096 CPU vs GPU vs OpenSSL 综合基准
- 新增 `benchmarks/bench_rsa_gpu.cpp`（280 行）：RSA GPU 批量基准
- benchmark 目标从 `tests/` 迁移至独立 `benchmarks/` 目录，新增 `benchmarks/CMakeLists.txt`（60 行）

### Changed

#### Ed25519 / X25519 重构与优化
- Ed25519 域运算重构为 radix-51 表示：新增 `src/fe_25519_r51.hpp`（368 行）、`src/ed25519_r51.cpp`（67 行），`src/ed25519.cpp` 精简约 580 行（删除旧 `ed25519_cpu.cpp`/`ed25519_avx2.cpp`）
- 新增 `src/x25519_body.inc`（83 行），`src/x25519.cpp` 重写并新增 `src/x25519_avx512.cpp`：X25519 支持 AVX512 加速
- 批量签名/验证分派与 `include/cpu_features.hpp` 同步更新

#### Ed448 优化
- `src/ed448.cpp`、`src/ed448_body.inc`、`src/fe_448.hpp` 域运算与实现优化（合计约 400 行变更）

#### RSA GPU 优化
- `src/rsa_gpu.mu` kernel 与 `src/rsa_musa.cpp` 主机封装重构优化（两轮共约 1300 行变更），并同步优化 `rsa_batch_avx2.cpp`/`rsa_batch_avx512.cpp`/`rsa_batch_dispatch.cpp` 批量分派

#### 构建
- `CMakeLists.txt`、`tests/CMakeLists.txt` 调整：benchmark 目标移出 tests，README 同步更新

### Fixed
- 修复 RSA 相关 bug（含密钥生成/批量模幂路径，经 `src/rsa.cpp`、`src/rsa_batch_dispatch.cpp` 等两轮修复）

---

## [0.9.1] — 2026-07-31

### Added

#### X.509 v3 证书 (RFC 5280)
- 新增 `include/x509.hpp`、`src/x509.cpp`（783 行）：完全自包含的 DER 编码器/解码器，支持 ASN.1 基本类型（INTEGER、OID、BIT STRING、OCTET STRING、UTF8String、UTCTime、SEQUENCE、SET），X.509 v3 证书生成、解析与证名链验证。
- 支持五种密钥类型：**RSA-2048/4096**、**Ed25519**、**Ed448**、**ECDSA P-256**、**SM2**
- 支持证书扩展：**BasicConstraints**（CA）、**KeyUsage**、**ExtendedKeyUsage**（serverAuth/clientAuth）、**SubjectAlternativeName**（DNS SAN）
- 单元测试 `tests/test_x509.cpp`（459 行，30+ 项测试）：DER 原语编解码、自签名证书生成与验证（Ed25519/ECDSA/SM2/Ed448/RSA）、TLS X.509 集成、证名链验证

#### TLS X.509 集成
- `tls_make_x509_self_signed(cert, days)`：从 `tls_certificate` 生成 X.509 v3 DER 自签名证名（含 SAN、KeyUsage、EKU）
- `tls_sig_alg_to_key_type(sig_alg)`：SignatureAlgorithm → X.509 KeyType 映射
- `tls12_make_certificate(cert)`：实现 TLS 1.2 Certificate 消息构建（此前面声明未实现）
- TLS 1.3 握手 `tls13_make_certificate()`：`cert_data` 为空时自动调用 `tls_make_x509_self_signed()` 生成 X.509 DER

#### 命令行工具
- **`jpssl-cert`** (`src/cmd/jpssl_cert.cpp`, 305 行)：X.509 证名生成（`gen`）、查看（`info`）、证名链验证（`verify`/`chain`）、TLS API 生成（`tlsgen`）
- **`jpssl-crypt`** (`src/cmd/jpssl_crypt.cpp`, 339 行)：AES-256-GCM/ChaCha20-Poly1305 加密解密（`encrypt`/`decrypt`）、哈希（`sha256`/`sha512`/`sha3`/`sm3`）、HMAC、随机数生成
- 支持自定义 IV/AAD/Tag 十六进制传入，加密输出 IV‖密文‖Tag 格式，解密自动提取
- `make install` 安装至 `<prefix>/bin/`

### Changed

#### MUSA 条件编译
- 新增 `-DJP_ENABLE_MUSA=ON` 选项（**默认 OFF**）：MUSA GPU 加速改为可选的实验性功能
- `#include <musa_runtime.h>` 及所有 MUSA 池函数在 `src/chacha20_poly1305.cpp` 中被 `#ifdef JP_MUSA` 守卫
- `musa4096_rsa_batch_modpow` 在 `src/rsa.cpp` 中被 `#ifdef JP_MUSA` 守卫
- `CMakeLists.txt` 中 MUSA 库目标、`jpssl-test`、命令行工具均条件编译

#### 测试结构重组
- 新增 `tests/CMakeLists.txt`（199 行）：所有单元测试与 benchmark 目标从主 `CMakeLists.txt` 中分离
- 主 `CMakeLists.txt` 使用 `add_subdirectory(tests)`
- 测试链接 `MUSA_LIBS` 变量（MUSA 关闭时为空）

#### README 更新
- 新增 X.509 v3 API 章节（4 个子章节：自签名证名生成、DER 解析、证名链验证、TLS 集成）
- 新增命令行工具章节（jpssl-cert 和 jpssl-crypt 的用法与示例）
- 新增条件编译章节：`JP_ENABLE_MUSA` 默认 OFF
- 算法总览表 GPU 加速列标注“实验性”，依赖章节标注 MUSA 为可选

### Fixed
- `tests/test_tls.cpp` 第 371 行 `sf_a.size()` → `sf_b.size()`：SNI 测试中因不同密钥类型的 X.509 DER 大小差异而暴露的旧 bug

---

## [0.9.0] — 2026-07-30

### Added
- 初始版本：AES、ChaCha20-Poly1305、RSA、TLS 1.2/1.3、Ed25519、ECDSA、SM2/3/4 国密算法
- CPU 优化（AES-NI、AVX2、AVX512、Montgomery CIOS）
- MUSA GPU 加速（AES、ChaCha20、RSA、SHA-512 kernel）
- CTest 单元测试集
