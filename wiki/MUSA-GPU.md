# MUSA GPU 加速（实验性）

JPSSL 支持可选的 **MUSA GPU 加速**（摩尔线程 MUSA 架构），默认关闭。该功能仅支持 Linux，Windows 上 `-DJP_ENABLE_MUSA=ON` 会被自动禁用并提示。

## 启用

需要 **MUSA SDK 4.3.0+**：

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DJP_ENABLE_MUSA=ON
cmake --build build

# 运行测试时指向 MUSA 运行库
LD_LIBRARY_PATH=/usr/local/musa/lib ctest --output-on-failure
```

构建集成：CMake 通过 `/usr/local/musa/cmake` 的 `find_package(MUSA)` 查找 SDK；MUSA 内核（`.mu` 文件）由 `mcc` 编译，`--offload-arch=mp_21 / mp_22 / mp_31`。

## GPU 内核

| 文件 | 内容 |
|------|------|
| `src/aes_gpu.mu` | AES ECB kernel |
| `src/chacha20_gpu.mu` | ChaCha20 keystream kernel |
| `src/rsa_gpu.mu` | RSA 批量模幂 kernel |
| `src/sha512_gpu.mu` | SHA-384/512 GPU kernel |
| `src/aes_musa.cpp` | AES 主机端封装 |
| `src/rsa_musa.cpp` | RSA GPU 封装 |
| `src/sha512_musa.cpp` | SHA-512 MUSA 封装 |

## 持久化池 API

为了避免每次调用重复分配 GPU 内存，库提供**持久化内存池**：

```cpp
// AES
auto* pool = musa_aes_pool_create(ctx, 64*1024*1024);
musa_aes_pool_encrypt_ecb(pool, input, output, num_blocks);

// ChaCha20
auto* cc = musa_chacha20_pool_create(key, nonce);
musa_chacha20_pool_xor(cc, input, output, num_blocks, 0);

// RSA（批量解密）
auto* rsa = musa_rsa_pool_create(prv, 1024);
musa_rsa_batch_decrypt(rsa, ciphers, plains, count);
```

## 宏守卫

所有 GPU 基准段（`bench_sha512` / `bench_hardware_accel` 中的 `musa_*` 调用、`bench_rsa_gpu` 目标）都由 `JP_MUSA` 宏守卫：`JP_ENABLE_MUSA=OFF`（默认）时自动跳过 GPU 段，基准程序仍可正常编译运行。

## 性能数据

在 MTT S80 + i7-13700K 上的实测（详见 [性能基准](Benchmarks)）：

| 算法 | CPU | GPU | 加速比 |
|------|-----|-----|--------|
| AES-128 ECB（16MB） | 5.5 GB/s（AES-NI） | 2.5 GB/s | — |
| ChaCha20（16MB） | 0.5 GB/s | 1.1 GB/s | 2.2× |
| RSA 2048 模幂 | 19 ms/op | 36 ms/op（batch） | — |
| RSA 4096 模幂 | 0.5 ms（e=65537） | — | — |

> GPU 加速目前为**实验性**：AES-ECB 尚不如 AES-NI，ChaCha20 在 GPU 上有 2.2× 加速，RSA 批量模幂主要面向批量解密场景。
