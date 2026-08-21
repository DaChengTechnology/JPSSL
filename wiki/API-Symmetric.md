# 对称加密 API

所有头文件位于 `include/` 目录，命名空间为 `jpssl`（部分 API 为全局函数，见各头文件）。

## AES（[FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final)）

头文件：`include/aes.hpp`

```cpp
#include "aes.hpp"

aes_context ctx;
ctx.init(std::span<const uint8_t,16>(key));

aes_cbc_encrypt(ctx, iv, plaintext, ciphertext);
aes_gcm_encrypt(ctx, iv, 12, plaintext, aad, ct, tag);
```

支持的密钥长度：128 / 192 / 256 位。支持模式：

- **ECB**：单块 / 批量加密
- **CBC**：PKCS#7 填充（`aes_cbc_encrypt` / `aes_cbc_decrypt`）
- **GCM**：AEAD 认证加密（[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38d/final)，软件 / AVX2 / AVX512 VAES 自动分派，`aes_gcm_auto.cpp`）
- **CCM**：AEAD 认证加密（[NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38c/final)，`include/aes_ccm.hpp`）

硬件加速：AES-NI + PCLMULQDQ（GCM GHASH）；AVX512 VAES GCM 8 路并行。

### GHASH / GF(2^128)（GCM 认证核心，见 [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38d/final)，可单独使用）

```cpp
uint8_t H[16], S[16];              // H = AES_encrypt(K, 0^128)

// 一次性 GHASH（末尾块自动补零）
ghash(H, data, S);

// 增量 GHASH（流式，分块喂入）
ghash_ctx g;
ghash_init(&g, H);
ghash_update(&g, aad.data(), aad.size());
ghash_update(&g, ciphertext.data(), ciphertext.size());
ghash_final(&g, S);

// 完整 GCM 认证哈希（含 AAD/密文分段补零与长度块，输出 GCM 的 S 值）
gcm_ghash(H, aad, ciphertext, S);
// 完整 GCM 标签：tag = S ^ AES_encrypt(K, J0)，J0 = IV || 0^31 || 1
```

底层原语 `gf128_mul`（PCLMULQDQ 加速的 GF(2^128) 乘法，NIST 大端序约定）同样公开，可用于自定义认证构造。

## ChaCha20-Poly1305（[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)）

头文件：`include/chacha20_poly1305.hpp`

```cpp
#include "chacha20_poly1305.hpp"

// AEAD 加密（[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439)）
chacha20_poly1305_encrypt(key, nonce, plaintext, aad, ct, tag);

// 纯流加密（ChaCha20 keystream XOR）
chacha20_stream_xor(key, nonce, input, output);
```

硬件加速：AVX2 / AVX-512 多块并行（`chacha20_avx2.cpp` / `chacha20_avx512.cpp`），Poly1305 有 AVX2 路径（`poly1305_avx2.cpp`）。

## SM4（[GM/T 0002-2012](https://www.oscca.gov.cn/)）

头文件：`include/sm4.hpp`、`include/sm4_gcm.hpp`、`include/sm4_ccm.hpp`

```cpp
#include "sm4.hpp"

uint8_t key[16];
sm4_ctx ctx; sm4_init(&ctx, key);

// 单块
uint8_t cipher[16], recovered[16];
sm4_encrypt_block(&ctx, plain, cipher);
sm4_decrypt_block(&ctx, cipher, recovered);

// ECB
std::vector<uint8_t> ct(plain.size());
sm4_ecb_encrypt(&ctx, std::span<const uint8_t>(plain), std::span<uint8_t>(ct));

// CBC + PKCS#7
uint8_t iv[16] = {};
auto ct = sm4_cbc_encrypt(&ctx, iv, std::span<const uint8_t>(msg, len));
auto pt = sm4_cbc_decrypt(&ctx, iv, std::span<const uint8_t>(ct));
```

### SM4-GCM AEAD（[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38d/final) 框架，SM4 见 [GM/T 0002](https://www.oscca.gov.cn/)）

```cpp
#include "sm4_gcm.hpp"

uint8_t key[16], iv[12], tag[16];
sm4_ctx ctx; sm4_init(&ctx, key);

std::vector<uint8_t> ct;
sm4_gcm_encrypt(&ctx, iv, 12,
    std::span<const uint8_t>(plaintext, pt_len),
    std::span<const uint8_t>(aad, aad_len),
    ct, tag, 16);

std::vector<uint8_t> recovered;
bool ok = sm4_gcm_decrypt(&ctx, iv, 12,
    std::span<const uint8_t>(ct),
    std::span<const uint8_t>(aad, aad_len),
    tag, 16, recovered);
```

SM4-GCM 遵循 [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38d/final)，GHASH 使用 PCLMULQDQ 快速路径（`sm4_gcm_dispatch.cpp` 自动分派），修复了非 96 位 IV 的 J0 构造（与 NIST SP 800-38D 一致）。

### SM4-CCM AEAD（[NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38c/final) 框架，SM4 见 [GM/T 0002](https://www.oscca.gov.cn/)）

```cpp
#include "sm4_ccm.hpp"

uint8_t key[16], nonce[12], tag[16];
sm4_ctx ctx; sm4_init(&ctx, key);

std::vector<uint8_t> ct;
sm4_ccm_encrypt(&ctx, nonce, 12,
    std::span<const uint8_t>(plaintext, pt_len),
    std::span<const uint8_t>(aad, aad_len),
    ct, tag, 16);

std::vector<uint8_t> recovered;
bool ok = sm4_ccm_decrypt(&ctx, nonce, 12,
    std::span<const uint8_t>(ct),
    std::span<const uint8_t>(aad, aad_len),
    tag, 16, recovered);
```

## Base64（[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)）

头文件：`include/base64.hpp`

```cpp
#include "base64.hpp"

std::string b64 = base64_encode(data, len);
auto decoded = base64_decode(b64);   // std::optional<std::vector<uint8_t>>
```

运行时按 AVX-512（含 BW）> AVX2 > 标量自动分派。AVX2 实测编码约 21–22 GB/s、解码约 17 GB/s（i7-13700K，对比标量编码约 3 GB/s、解码约 0.2 GB/s）。尾部与 `=` 填充仍走标量，语义与常规 base64 完全一致。
