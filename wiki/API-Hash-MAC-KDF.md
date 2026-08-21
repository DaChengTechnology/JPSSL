# 哈希 / MAC / KDF API

## SHA-1（[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/final)）

头文件：`include/sha1.hpp`

```cpp
#include "sha1.hpp"

sha1_ctx ctx; sha1_init(&ctx);
sha1_update(&ctx, data, len);
uint8_t digest[20]; sha1_final(&ctx, digest);
std::string hex = sha1_hex(digest);       // "a9993e364706816aba3e25717850c26c9cd0d89d"
```

加速：`src/sha1_avx2.cpp`（8 路多缓冲，YMM 每 lane 一条消息）与
`src/sha1_avx512.cpp`（16 路多缓冲，ZMM）。等长批量哈希可通过
`sha1_batch` 自动分派：

```cpp
const uint8_t* msgs[16] = {...};
uint8_t outs[16][20];
sha1_batch(msgs, len, &outs[0][0], 16);   // AVX-512 16 路 > AVX2 8 路 > 标量
```

## SHA-256（[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/final)）

头文件：`include/sha256.hpp`

```cpp
#include "sha256.hpp"

sha256_ctx ctx; sha256_init(&ctx);
sha256_update(&ctx, data, len);
uint8_t digest[32]; sha256_final(&ctx, digest);
```

硬件加速：SHA-NI（`sha256_sha_ni.cpp`，`__x86_64__ || _M_X64` 时编译）。

## SHA-384 / SHA-512（[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/final)）

头文件：`include/sha512.hpp`

```cpp
#include "sha512.hpp"

sha512_ctx ctx;
sha512_init(&ctx);  // 或 sha384_init 得到 SHA-384
sha512_update(&ctx, data, len);

uint8_t hash[64]; sha512_final(&ctx, hash);  // 输出: SHA-512 64 字节; SHA-384 48 字节
std::string hex = sha512_hex(hash);          // "e718483d0ce769..."
```

硬件加速：SSE4.1 SIMD 消息调度（`sha512_opt.cpp`）。

## SHA3-256 / 384 / 512（[FIPS 202](https://csrc.nist.gov/pubs/fips/202/final)）

头文件：`include/sha3.hpp`

```cpp
#include "sha3.hpp"

sha3_ctx ctx;
sha3_256_init(&ctx);  // 或 sha3_384_init / sha3_512_init
sha3_update(&ctx, data, len);

uint8_t hash[64]; sha3_final(&ctx, hash);
```

## SM3（[GM/T 0004-2012](https://www.oscca.gov.cn/)）

头文件：`include/sm3.hpp`

```cpp
#include "sm3.hpp"

// 一次性哈希
uint8_t digest[32]; sm3_hash(digest, (const uint8_t*)data, len);

// 增量哈希
sm3_ctx ctx; sm3_init(&ctx);
sm3_update(&ctx, data, len);
sm3_final(&ctx, digest);
std::string hex = sm3_hex(digest);
```

性能：MSVC x64 下 `sm3_cf` 自动走 MASM 标量汇编（`src/sm3_win.asm`，64 轮全展开），8 KiB 吞吐约 390 MB/s；GCC/Clang 下使用 8 轮展开 + 常量折叠，吞吐与 OpenSSL 持平。

## HMAC（[RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) / [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final)）

头文件：`include/hmac.hpp`

```cpp
#include "hmac.hpp"

uint8_t mac[32]; hmac_sha256(key, 32, msg, len, mac);
uint8_t mac384[48]; hmac_sha384(key, 48, msg, len, mac384);
uint8_t mac_sm3[32]; hmac_sm3(key, 32, msg, len, mac_sm3);
```

## HKDF（[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)）

头文件：`include/hkdf.hpp`

```cpp
#include "hkdf.hpp"

// SHA-256
uint8_t prk[32]; hkdf_extract(salt, 16, ikm, 32, prk);
uint8_t okm[64]; hkdf_expand(prk, info, 8, okm, 64);

// SHA-384（用于 TLS 1.3 AES-256-GCM 等套件）
uint8_t prk384[48]; hkdf_extract_sha384(salt, 16, ikm, 32, prk384);
uint8_t okm384[64]; hkdf_expand_sha384(prk384, info, 8, okm384, 64);

// SM3（用于 TLS 1.3 [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) 国密套件）
uint8_t prk_sm3[32]; hkdf_extract_sm3(salt, 16, ikm, 32, prk_sm3);
uint8_t okm_sm3[64]; hkdf_expand_sm3(prk_sm3, info, 8, okm_sm3, 64);
```

## 随机数

头文件：`include/rand_os.hpp`

```cpp
#include "rand_os.hpp"

// Windows: BCryptGenRandom; Linux: /dev/urandom
jpssl::os_rand_bytes(buffer, len);
```

所有密钥生成 / 签名 nonce 均使用该操作系统随机源，**不要**使用 MSVC 的 `std::random_device`（确定性的）。
