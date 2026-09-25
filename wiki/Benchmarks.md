# 性能基准

基准程序位于 `benchmarks/`，通过 `JP_ENABLE_BENCH` 开关构建（默认 OFF）：

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DJP_ENABLE_BENCH=ON
cmake --build build
```

## 基准目标

| 目标 | 内容 |
|------|------|
| `bench_rsa_cpu_gpu` | RSA CPU vs GPU vs OpenSSL 综合基准（2048/4096 私钥、2048 公钥） |
| `bench_rsa_gpu` | RSA-2048/4096 CPU 批量 vs MUSA GPU 批量（仅 `JP_ENABLE_MUSA=ON` 时构建） |
| `bench_sha512` | SHA-512 CPU vs SSE4.1 SIMD；GPU 单块/批量（仅 MUSA 构建） |
| `bench_hardware_accel` | AES / ChaCha20-Poly1305 / SHA-512 硬件加速路径对比（GPU 段仅 MUSA 构建） |
| `bench_cipher_suites` | TLS 密码套件性能 |
| `bench_sm4` | SM4（ECB/GCM）vs OpenSSL |
| `bench_base64` | base64 编解码：标量 vs AVX2 vs AVX512 vs 自动分发 |
| `bench_sm_ossl` | SM3 吞吐 + SM2 keygen/sign/verify vs OpenSSL |
| `bench_ed25519_ossl` | Ed25519 签名/验证 vs OpenSSL（仅找到 OpenSSL 时构建） |
| `bench_ed448_x448_ossl` | Ed448 / X448 vs OpenSSL（仅找到 OpenSSL 时构建） |
| `bench_x25519_ossl` | X25519 ECDH vs OpenSSL（仅找到 OpenSSL 时构建） |

## 已公布的实测数据

### 平台：MTT S80（GPU）+ i7-13700K（CPU）

| 算法 | CPU | GPU | 加速比 |
|------|-----|-----|--------|
| AES-128 ECB（16MB） | 5.5 GB/s（AES-NI） | 2.5 GB/s | — |
| ChaCha20（16MB） | 0.5 GB/s | 1.1 GB/s | 2.2× |
| RSA 2048 模幂 | 19 ms/op | 36 ms/op（batch） | — |
| RSA 4096 模幂 | 0.5 ms（e=65537） | — | — |

### 对 OpenSSL 的对比结论（来自提交历史 / README）

| 项目 | 结果 |
|------|------|
| SM2 keygen / sign / verify | 相对旧实现提速 84× / 83× / 135×；对 OpenSSL 4.0 反超 1.31× / 1.35× / 1.26× |
| SM3 压缩函数 | 8 轮展开 + 常量折叠，吞吐与 OpenSSL 持平；MSVC 汇编路径约 390 MB/s |
| SM4 ECB / GCM | 吞吐均反超 OpenSSL 约 1.2–1.3× |
| SM4-GCM GHASH | PCLMULQDQ 快速路径 |
| RSA CRT 解密 | 半尺寸汇编 + OpenMP 双线程，2048/4096 解密提速 1.5–1.7× |
| RSA CRT 私钥签名 | PKCS#1 完整私钥自动携带 CRT 参数，RSA-2048 私钥签名 2186ms → 3ms、PSS 2436ms → 1ms（1.1.9） |
| Base64 | AVX2 编码约 21–22 GB/s、解码约 17 GB/s（vs 标量编码约 3 GB/s、解码约 0.2 GB/s） |

## 说明

- 所有 GPU 基准段由 `JP_MUSA` 宏守卫，MUSA 关闭时自动跳过，程序仍可编译运行。
- OpenSSL 对比基准仅在系统找到 OpenSSL 时构建。
- CI 中 Windows 的基准 job 只构建不运行（`ctest -E bench`），避免 CI 负载下的计时波动导致偶发失败。
