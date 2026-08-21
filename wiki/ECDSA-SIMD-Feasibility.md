# ECDSA AVX2 / AVX512 可行性探索

> 范围：P-256 / P-384 / P-521（`src/ecdsa.cpp`），重点是 P-256（TLS 握手与证书链中最常用）。
> 结论先行：**AVX2 可行且推荐**（作为批量验证/多缓冲加速层，本机可测）；**AVX512 技术上可行但属后续可选阶段**（本机 Raptor Lake 桌面无 AVX512，无法本地验证）。无论哪条 SIMD 路线，**第一步都必须是标量算法升级**——当前实现的瓶颈不是缺 SIMD，而是基础算法（逐比特归约 + 无窗口 double-and-add）。

## 1. 现状与基线

当前 `ecdsa.cpp` 为通用 `uint256`（4×u64）+ Jacobian 坐标：

- `mm_mul` 走 512 位全乘 + `mod_reduce_512` **逐比特**移位比较减法归约（512 轮）；
- 标量乘是无窗口、逐 bit 的 left-to-right double-and-add（256 次倍点 + 约 128 次点加）；
- 验签是两个独立标量乘（`u1*G`、`u2*Q`）再相加，未用 Shamir 双标量；
- `G` 无预计算表。

本机实测（i7-13700K，MSVC Release /O2，64 字节消息，jpssl vs OpenSSL 4.x）：

| 曲线 | jpssl keygen | jpssl sign | jpssl verify | OSSL keygen | OSSL sign | OSSL verify | verify 差距 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P-256 | 15.9 ms | 17.5 ms | 31.4 ms | 5.9 µs | 14.2 µs | 40.8 µs | **约 770×** |
| P-384 | 49.7 ms | 55.3 ms | 98.6 ms | 505 µs | 527 µs | 462 µs | 约 213× |
| P-521 | 5.5 ms | 19.3 ms | 24.2 ms | 1068 µs | 1126 µs | 930 µs | 约 26× |

（OpenSSL 的 P-256 走 `ecp_nistz256` 专用汇编；P-384/P-521 走通用路径，所以差距相对小。交叉验证：jpssl 可正确验证 OpenSSL 产生的签名，`test_ecdsa` 全过。）

结论：**先做标量升级就能拿到 2~3 个数量级的收益**，与 SIMD 无关。本仓库 SM2 已经做过同样的事（Montgomery CIOS + wNAF-5 + Shamir + 批量仿射化，提速 84x/83x/135x，见 `src/sm2.cpp`），P-256 可直接移植该模式。

## 2. ECDSA 为什么适合（又为什么难）做 SIMD

适合：

- ECDSA 验签/签名的核心是**多个相互独立的 256 位标量乘**，天然适合“多缓冲”（multi-buffer）或“多通道”（lane-parallel）：AVX2 一个 YMM 寄存器同时算 4 个元素，AVX512 一个 ZMM 同时算 8 个。
- 批量验证（一次验 N 个签名）时，还有算法级共享：所有签名共享同一条倍点链（多标量乘法 MSM）。

难点：

- P-256 素数 `p = 2^256 - 2^224 + 2^192 + 2^96 - 1` 不是 Mersenne 类素数，SIMD 下需要专用折叠归约或 Montgomery 归约，不能像 Ed25519/Ed448 那样简单折回；
- 单个标量乘内进位链长、依赖强，**编译器自动向量化基本无望**，必须手写内建函数；
- 签名路径有秘密标量，SIMD 点运算必须保持常数时间（无秘密相关的分支/表索引）；
- 单个操作（不批量）的并行度有限，SIMD 单签收益远小于批量收益。

## 3. 三条技术路线

### 路线 A：标量算法升级（先决条件，无 SIMD）

把 `sm2.cpp` 的模式移植到 P-256（通用曲线 P-384/P-521 同样受益）：

- Montgomery 乘法（CIOS，现有 `mont_mul`/`mont_reduce` 可直接改参数化）；
- wNAF-5 窗口标量乘；`G` 的奇倍点表**全局预计算**（仿射表 + 混合加法）；
- 验签用 Shamir 双标量同时乘（共享倍点），替代两个独立标量乘；
- 批量仿射化（一次求逆换 N 个逆），为批量验证做准备；
- 顺手修复签名路径的常数时间问题（当前逐 bit 分支依赖秘密标量）。

预期：P-256 verify 从 ~31 ms 降到亚 0.2 ms 量级（参考 SM2 的经验量级），且所有曲线、所有平台通用。

### 路线 B：批量验证 `ecdsa_p256_batch_verify`（MSM，与指令集无关）

算法：Bellare–Garay–Rabin 小指数测试。给每条签名取随机权重 `t_i`（128 位），一次检查

`Σ t_i·(u1_i·G + u2_i·Q_i − R_i) == O`

成立则全部接受；任一条无效时以 ≥ 1 − 2^-128 的概率拒绝。实现为一条共享倍点链的 MSM：

- 单个标量 `Σ t_i·u1_i mod n` 乘固定基点 `G`（可用预计算表）；
- N 个 `t_i·u2_i mod n` 乘各自的 `Q_i`，加负的 `t_i·R_i`；
- 逆元用批量求逆（1 次求逆 + N 次乘法）；
- 分块大小参照 `ed25519_batch`（128 条/块）。

收益：批量吞吐约为逐条验证的 2~4 倍（块越大越接近理论共享收益）。**指令集无关**——本仓库 Ed25519 批验证的结论就是“多标量批验证对指令集不敏感”，AVX512 后端最终只是保留兼容 API。该路线同样直接适用于 P-384/P-521。

### 路线 C：SIMD 字段层（沿用 `fe_448_simd.hpp` 模式）

#### C1：AVX2 4 通道，radix-2^26 × 10 肢体 + Montgomery

- 256 位素数用 10 个 26 位肢体表示；一次乘法肢体积 ≤ 52 位，schoolbook 列累加 ≤ 10×2^52 < 2^56，**64 位 lane 内无进位链**，进位传播全部可向量化（移位 + 掩码）；
- 每个 YMM 寄存器放 4 个独立元素的同一肢体（lane-sliced 布局，与 `fe_448_simd.hpp` 完全一致），寄存器压力约 10×3，可接受；
- 参考先例：ACISP 2020（Huang–Liu–Hu–Großschädl）用 AVX2 2-way radix-2^26 实现 SM2（同为 Weierstrass 曲线）：2-way 字段运算比串行快 1.25–1.60×，Co-Z Montgomery 阶梯快 1.31×，且抗时序/SPA；Gueron–Krasnov（J. Cryptogr. Eng. 2015）的 P-256 定点标量乘用窗口 7 + AVX2 引擎并行执行 4 个点加法；
- 本机 13700K 支持 AVX2（CPUID 实测 AVX2=1），**可直接开发与回归**。

#### C2：AVX512F 8 通道（同一抽象层换 `__m512i`）

- 结构不变，lane 数 4→8；需要 AVX512F + VL（Ice Lake+ / Zen 4+）；
- 本机（Raptor Lake 桌面）**AVX512 全系被固件熔断**（CPUID 实测 AVX512F=0，XCR0 无 opmask/ZMM），无法本地运行，需远程 CI 或服务器验证。

#### C3：AVX512-IFMA，radix-2^52/2^51 × 5 肢体（`vpmadd52luq/huq`）

- 两条 IFMA 指令直接把 52×52→104 位乘积的低/高 52 位累加进 64 位 lane，单次字段乘的指令数最少（5×5 schoolbook = 25 luq + 25 huq）；
- 成熟先例：
  - Intel IPP Crypto Multi-buffer（`intel/ipp-crypto` 的 crypto_mb）：`mbx_nistp256_ecdsa_sign_mb8` 等，AVX512-IFMA 8 缓冲 ECDSA/ECDH（P-256/384/521），已用于 QAT 引擎的软件加速；
  - `asmcrypto`（Rust，Zen 5 实测）：8-lane 批量 ECDSA 恢复约 15.6 µs/lane，比 8 次串行标量恢复（52.6 µs/lane）快约 3.4×，比逐条调优的 libsecp256k1 快约 1.4×；
  - curve25519-dalek 的 IFMA 笔记给出完整 radix-2^51 乘/平方/归约推导。
- 工具链：**MSVC 14.51 已实测可编译 IFMA 内建函数**（`/arch:AVX512` 下 `_mm512_madd52lo/hi_epu64` 编译通过）；GCC/Clang 长期支持。
- 硬件面：Intel Ice Lake / Tiger Lake / Rocket Lake / Sapphire Rapids，AMD Zen 4+（Zen 4 的 512 位按 2×256 执行、无明显降频；早期 Cannon Lake 半速执行 512 位 IFMA）。

### 路线对比

| 路线 | 收益量级 | 成本/风险 | 平台面 | 本机可测 |
| --- | --- | --- | --- | --- |
| A 标量升级 | verify 31 ms → <0.2 ms（数十倍） | 低；代码量大但模式现成（sm2） | 全平台 | 是 |
| B 批量 MSM | 批量吞吐 2–4× | 低；需随机数/常数时间权重 | 全平台 | 是 |
| C1 AVX2 4-lane | 批处理再 2–3×（单签为辅） | 中；字段层 + 点运算重写 | AVX2（2013 年后几乎所有 x86） | 是 |
| C2 AVX512F 8-lane | C1 的约 1.5–1.8× | 中；双份寄存器宽度代码 | Ice Lake+ / Zen 4+ | 否 |
| C3 AVX512-IFMA | 8-lane 多缓冲约 3.4×/通道（对照串行） | 高；52 位冗余表示 + 多缓冲框架 | 需 IFMA（Ice Lake+ / Zen 4+） | 否 |

## 4. 与现有代码的契合点

- 字段层抽象：`src/fe_448_simd.hpp`（`jf448_v`/掩码/比较/混合指令的 AVX2↔AVX512 条件编译）→ 可照搬为 `fe_p256_simd.hpp`；
- 分发机制：`include/cpu_features.hpp`（AVX2/AVX512/ADX 运行时检测）+ `ed448_batch_dispatch.cpp` 的“AVX512 > AVX2 > 标量”优先级 + `CMakeLists.txt` 按源文件设 `/arch:AVX2`、`/arch:AVX512`；
- 批量验证模板：`ed25519_batch`（随机盲化 MSM、128 条/块、批量求逆）与 `ed448_batch`（SIMD 后端 + 分发）可分别提供“算法层”和“SIMD 层”两个样板；
- 标量内核：`src/sm2.cpp` 的 CIOS Montgomery、wNAF-5、Shamir、批量仿射是 P-256 的直接模板（SM2 与 P-256 同构，仅素数不同）。

## 5. 风险与注意事项

- **不要给慢内核叠 SIMD**：OpenSSL 曾因 `ecp_nistz256.c` 中 AVX2 代码不可达/收益存疑而整体移除（PR #12046）。SIMD 必须叠加在升级后的标量内核上，否则只是“给逐比特归约加速”。
- **签名常数时间**：当前 sign 的逐 bit 分支已非常数时间（侧信道风险，与 SIMD 无关），标量升级时应一并改成固定窗口/阶梯。
- **AVX512 部署面**：Raptor Lake/Alder Lake 桌面熔断 AVX512；老 Xeon 的 512 位指令有降频代价；AMD Zen 4+ 无此问题但按 2×256 执行。C2/C3 代码在本机无法运行，必须靠 CI 或服务器回归。
- **编译器不会替你向量化进位链**：全部走手写内建函数（现有 `fe_448_simd.hpp`、`rsa_batch_avx512.cpp` 风格）。
- **P-384/P-521**：路线 B（批量 MSM）直接适用；路线 C 的 radix-2^26 需要 15/21 个肢体，寄存器压力大、收益递减，建议优先级放低。
- **维护成本**：每一档 ISA 都是一份字段层 + 点运算代码，建议用模板/宏复用点公式（如 `ed448_simd_body.inc` 的 include 复用方式），避免三份点公式漂移。

## 6. 建议路线图

| 阶段 | 内容 | 目标 | 验证 |
| --- | --- | --- | --- |
| 0 | 新增 `benchmarks/bench_ecdsa_ossl.cpp`（对标 `bench_ed25519_ossl`） | 建立 jpssl vs OpenSSL 基线 | ✅ 本机 |
| 1 | 标量升级：Montgomery CIOS + wNAF-5 + G 定点表 + Shamir + 修 CT | P-256 verify < 0.2 ms | ✅ 本机 + `test_ecdsa` |
| 2 | `ecdsa_p256_batch_verify`（MSM、随机权重、批量求逆、128/块） | 批量吞吐 2–4× | 本机 |
| 3 | `fe_p256_simd.hpp` AVX2 4-lane + 批量/多缓冲后端 + 分发 | 批量再 2–3× | 本机（AVX2） |
| 4 | AVX512F 8-lane 变体；可选 AVX512-IFMA 多缓冲（面向 Ice Lake+/Zen4+ 服务器） | 8-lane 吞吐 | 远程 CI/服务器 |

### Phase 1 实测结果（i7-13700K，MSVC Release，`benchmarks/bench_ecdsa_ossl.exe`）

| 曲线 | 操作 | 旧实现 | 新实现 | 提升 | OpenSSL 4.x | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| P-256 | keygen | 15.9 ms | 170 µs | 约 93× | 5.9 µs | nistz256 专用汇编 |
| P-256 | sign | 17.5 ms | 190 µs | 约 92× | 14.1 µs | 固定 4-bit 窗口 CT 路径 |
| P-256 | verify | 31.4 ms | 193 µs | 约 163× | 40.6 µs | **达标（<0.2 ms）** |
| P-384 | keygen | 49.7 ms | 509 µs | 约 98× | 505 µs | 与 OpenSSL 持平 |
| P-384 | sign | 55.3 ms | 571 µs | 约 97× | 527 µs | 与 OpenSSL 持平 |
| P-384 | verify | 98.6 ms | 611 µs | 约 161× | 465 µs | 与 OpenSSL 持平 |
| P-521 | keygen | 5.5 ms | 973 µs | 约 5.7× | 1071 µs | 略快于 OpenSSL |
| P-521 | sign | 19.3 ms | 1093 µs | 约 18× | 1127 µs | 略快于 OpenSSL |
| P-521 | verify | 24.2 ms | 1166 µs | 约 21× | 927 µs | 接近 OpenSSL |

- 三条曲线与 OpenSSL 双向互操作验证通过（`test_ecdsa` 17 项全过；TLS 136 / X.509 60 / CT 95 / OpenSSL 对比 22 项全过）。
- 实现要点：模板化 `bn<N>`（N=4/6/9）+ Montgomery CIOS（R=2^(64N)）；验签 wNAF-5 + Shamir 共享倍点链；签名/密钥生成固定 4-bit 窗口 + 常数时间表选择（窗口数固定、无秘密索引，仅 H==0 例外分支为 ~2^-N 概率的残余数据相关分支，与 `sm2.cpp` 一致）；G 的 1..15 倍仿射表懒预计算；验签末尾用射影比较 `X == r·Z²` 免去一次 Fermat 求逆。
- 说明：P-256 仍落后 OpenSSL（nistz256 为专用归约汇编 + ADX），进一步缩小差距需手写 4-limb CIOS/FIOS 微优化或汇编，属后续阶段；P-384/P-521 已与 OpenSSL 通用路径持平。

### Phase 1.5：P-256 特殊形式归约（nistz256 风格，C++ 版）

给 P-256 的素数域换上 Gueron–Krasnov / nistz256 特殊形式 Montgomery 归约
（`p256_reduce_special`，常数 `0xffffffff00000001`，4 轮低字折叠 + 条件减 p，
参照 Go `p256_asm_amd64.s`；经 1 万组随机输入与通用 Montgomery 对照验证）。
mod n（群阶）仍走通用 CIOS。

| 曲线 | 操作 | Phase 1 | Phase 1.5 | 提升 | OpenSSL 4.x |
| --- | --- | --- | --- | --- | --- |
| P-256 | keygen | 169.5 µs | **97.4 µs** | 1.74× | 5.9 µs |
| P-256 | sign | 190.2 µs | **118.3 µs** | 1.61× | 14.1 µs |
| P-256 | verify | 194.8 µs | **116.2 µs** | 1.68× | 40.6 µs |

verify 的时间分布（实测）：wNAF 双标量（256 倍点 + ~170 混合加）约 84 µs、
mod-n 求逆约 17 µs、Q 的奇倍表约 14 µs、哈希约 0.4 µs。

**与 OpenSSL 差距的归因**：当前 C++ 域乘（16 次 `_umul128` + 折叠）约 22 ns
（≈75–100 周期），nistz256 汇编（MULX/ADCX/ADOX + 操作数扫描乘积）约 15–20 周期；
点公式（dbl-2001-b / add-2007-bl）双方相同。因此主要差距在域运算速度，若要追平
OpenSSL 需要 MASM ADX 域核心（仓库已有先例 `fe51_mul_adx.asm` / `rsa_mont_asm_win.asm`），
预期 verify 可到 ~45–55 µs。这属于下一阶段（Phase 1.6），工作量约半个到一个工作日。

### Phase 1.6：MASM ADX 域核心（已完成）

新增 `src/ecdsa_p256_adx.asm`：`jpssl_p256_mul_adx`，结构来自 OpenSSL
`ecp_nistz256-x86_64.pl` 的 `__ecp_nistz256_mul_montx`（交错 CIOS + 特殊归约，
MULX/SHLX/SHRX + ADCX/ADOX 双进位链），按 Windows x64 寄存器重映射。
`mont_mul` 在 `M.special && cpu_has_adx()` 时走汇编，否则回退 C++ 特殊归约；
GCC/Clang 平台不受影响（仍用 C++ 路径）。2 万组随机输入与通用 Montgomery 对拍通过。

| P-256 | Phase 1.5 | Phase 1.6（ADX asm） | OpenSSL 4.x | 差距 |
| --- | --- | --- | --- | --- |
| keygen | 97.4 µs | **56.0 µs** | 5.9 µs | 9.4× |
| sign | 118.3 µs | **77.0 µs** | 14.1 µs | 5.5× |
| verify | 116.2 µs | **63.4 µs** | 40.7 µs | **1.56×** |

相对原始实现：verify 31.4 ms → 63.4 µs（约 495×）、keygen 15.9 ms → 56 µs（约 284×）、
sign 17.5 ms → 77 µs（约 227×）。域乘 ~8.4 ns（约 35–40 周期，已与 nistz256 同量级），
jac_dbl 153 ns。

**残余差距归因**：1) `jac_dbl` 实测 153 ns vs 8 次域乘理论 ~67 ns——MSVC 对点公式
（多临时变量）的代码生成有 ~2 倍开销，点运算本身写成汇编可再砍一半；2) mod n 求逆
仍走通用 CIOS（约 27 ns/次，未用特殊归约）；3) 签名/密钥生成的固定 4-bit 窗口
（64 次加法）不如 nistz256 的 8-bit 固定基表。若三者都做，verify 可望接近 40 µs。

### Phase 1.7：三项收尾优化（已完成）

1. **mod n（群阶）ADX 归约**：`jpssl_p256_ord_mul_adx`（转写 `ecp_nistz256_ord_mul_montx`，
   K0 = 0xccd1c8aaee00bc4f + n 的 4 字），mod n 域乘 ~27 → 11.6 ns，mod_inv n 17 → 6.2 µs；
2. **点运算汇编**：`jpssl_p256_dbl`（dbl-2001-b，9 次域乘 + 模加减全调度在栈帧/寄存器）与
   `jpssl_p256_madd`（混合加，P 无穷远走固定模式分支、Q 无穷远走无分支掩码、H==0 走可忽略分支），
   dbl 155 → 140 ns、madd 157 → 149 ns；
3. **固定基点窗口组合（comb）**：预计算 64×15 个仿射点 `d·2^(4k)·G`（61KB，懒构建），
   热点路径零倍点、64 次混合加 + CT 选点，keygen/sign 的固定基部分约 48 → 10 µs。

最终（i7-13700K，MSVC Release，与 OpenSSL 4.x 同机对比）：

| P-256 | 原始 | 最终 | 累计提升 | OpenSSL 4.x | 差距 |
| --- | --- | --- | --- | --- | --- |
| keygen | 15.9 ms | **15.9 µs** | 约 1000× | 5.9 µs | 2.7× |
| sign | 17.5 ms | **23.1 µs** | 约 758× | 14.1 µs | 1.6× |
| verify | 31.4 ms | **51.1 µs** | 约 614× | 40.8 µs | **1.25×** |

全套测试（test_ecdsa 17 项、X.509 60、CT 95、ossl_verify 7/7、SM、OpenSSL 对比 22）通过，
双向互操作 PASS。残余差距主要是域乘仍未内联进点公式（每点运算 ~10 次函数调用），
以及 nistz256 的定点表更大（本实现为 CT 选点约束所限）。

### Phase 2：ECDSA 接入 TLS 密钥交换（已完成）

TLS 的 ECDSA 此前只用于证书签名/握手认证（0x0403/0503/0603，CertificateVerify），
ECDHE 密钥交换仅支持 X25519/X448/curveSM2。本轮补齐：

- **ECDHE 共享密钥 API**：`ecdsa_p256_ecdh` / `ecdsa_p384_ecdh`
  （shared = X(priv·pub)，[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) §4.2.8.2 定义；与 OpenSSL `ECDH_compute_key` 对拍通过）；
- **命名组**：`NamedGroup::secp256r1(0x0017)` / `secp384r1(0x0018)`，客户端
  `tls_session.ks_group` 设为对应组即启用；key_share 采用 [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) 裸 x||y 格式
  （P-256 64B / P-384 96B，无 0x04 前缀）；
- **服务端协商**：优先级 SM2 > secp256r1 > secp384r1 > X448 > X25519；
- **测试**：TLS 1.3 完整握手（P-521 证书 + P-256/P-384 ECDHE）新增 20 项断言，
  test_tls 136 → **156 项全过**；test_ecdsa 新增 ECDH 与 OpenSSL 对拍（P-256/P-384 均 PASS）。

### Phase 3：ECDHE 批量/多缓冲加速（第二种方案，本地可验证部分已完成）

针对「ECDHE 能否做汇编加速、能快多少」的结论：单条操作受限于 4-limb 依赖链，汇编收益约 25–30%；
真正能拉开差距的是**批量/多缓冲**（multi-buffer）——把 N 条 ECDH 打包，块内共享求逆。本轮按第二种方案交付：

- **批量 API**：`ecdsa_p256_ecdh_batch` / `ecdsa_p384_ecdh_batch`
  （shared/priv/pub 连续数组；pub 为裸 x||y，与 [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) key_share 一致；count ≥ 1，内部按 16 条一块）；
- **实现**：块内建 8n 个奇倍点表（Jacobian，仅 madd 不求逆）→ `batch_affine_many` 整批 1 次 Fermat 求逆
  → 各自 wNAF-5 → 输出再整批 1 次求逆。每 16 条仅 2 次求逆（逐条需 32 次）；Z==0 的异常点逐点回退保持正确性；
- **验证**：test_ecdsa Test 19（批量 vs 逐条对拍 N=17 覆盖尾部块，P-256/P-384 全 PASS，
  批量[0] 与 OpenSSL ECDH_compute_key 一致）；bench_ecdh_batch 逐字节核对 PASS。

实测（i7-13700K，MSVC Release /O2，`benchmarks/bench_ecdh_batch.exe`）：

| 曲线 | 模式 | N=100 ns/op | N=1000 ns/op | vs 逐条 | vs OpenSSL |
| --- | --- | --- | --- | --- | --- |
| P-256 | 逐条 | 55.4 µs | 54.6 µs | 1.00× | 0.55× |
| P-256 | 批量 | 46.3 µs | 46.2 µs | **1.20×** | 0.66× |
| P-384 | 逐条 | 552.7 µs | 560.8 µs | 1.00× | 0.92× |
| P-384 | 批量 | 436.7 µs | 439.1 µs | **1.27×** | **1.16×** |

（OpenSSL 同机同源参考：P-256 ≈ 30.6 µs、P-384 ≈ 507 µs。）

**关于"逐条 55 µs 比之前 42.8 µs 慢"的说明**：per-op 代码路径未变，差异来自测量对象。
固定同一把密钥实测 42.5 µs（与旧基线一致）；轮转 100/1000 把不同密钥时，wNAF 主循环的数据相关分支
（wnaf5 奇偶测试、`d>0/d<0`、`pt_madd` 内部分支）无法被分支预测器跟踪，每次调用多付约 11 µs 惩罚：
K=2 轮转 43.0 µs，K=16 即跳到 53.2 µs，K≥256 稳定在 54.7–55.2 µs；
同一批密钥逐把连续测 64 次平均 43.2 µs。批量 vs 逐条（1.20×）是公平对比（两边都轮转不同密钥）；
真实多变密钥场景下进一步提速应把 wNAF 换成固定窗口 + 常数时间选点（无数据分支），可同时消除该惩罚与时序侧信道。

**结论与后续**：纯标量批量已摊薄每条 2 次求逆（约 9 µs/条），P-256 约 1.20×、P-384 约 1.27× 吞吐提升，
P-384 批量已反超 OpenSSL。批量收益目前受限于 wNAF 主循环本身仍为串行标量；
再上 2–4× 需叠 AVX2 4-lane / AVX512-IFMA 8-lane 字段内核（路线 C），
其中 AVX512-IFMA 多缓冲约 3.4×/lane（对照 IPP crypto_mb 与 asmcrypto 数据），
本机 Raptor Lake 无 AVX512，该部分留待远程 CI/服务器验证。

### Phase 3.1：单次 ECDH 加速——点运算汇编无分支化（已实现）

上节发现"逐条 55 µs vs 固定密钥 42.8 µs"的分支惩罚后，进一步定位到根因：
`jpssl_p256_dbl` / `jpssl_p256_madd` 汇编里的**特殊归约用了数据相关条件跳转**
（`cmp/ja/jb/jne` 的"比较后决定是否减 p"，每个 dbl 约 6 个归约块、每个 madd 约 5 个）。
密钥固定时分支结果恒定、预测全中（42.5 µs）；每次换密钥时全部猜错（54.7 µs，+12 µs）。

**修复**：把 15 个 dbl 归约块 + 2 个宏 + 7 个 madd 内联块全部改成无分支：
- 减法归约：`setc` 保存借位 → `neg` 重建 CF → 4 条 `cmovc` 选择 r 或 r+p；
- 加法归约：`t = r - p` 后按 `borrow & ~carry_out` 掩码加回 p（a,b<p 时 carry_out==1 必然 borrow==1，掩码逻辑闭合）；
- 保留 madd 的 P 无穷远 / H==0 罕见分支（概率 ~2^-N，恒定可预测）。

验证：20k 随机点 asm vs C++ 对拍 + 边界（dbl(inf)、madd(inf,A)、madd(A,inf)、madd(A,A)、madd(A,-A)）+ 200 组 ECDH 自检全过；
test_ecdsa 19 项、test_tls 156 项全过。

实测（i7-13700K，MSVC Release，同会话 A/B：stash 旧 asm → 重建 → 测 → 恢复新 asm → 重建 → 测）：

| 场景 | 旧（分支版） | 新（无分支版） | 变化 |
| --- | --- | --- | --- |
| ECDH 固定同一密钥循环（微基准） | 42.5 µs | 48.7 µs | +15%（掩码指令开销 > 完美预测分支） |
| ECDH 完全随机密钥（微基准 K≥256） | 54.7 µs | 49.6 µs | −9% |
| ECDH 轮转 100 把密钥（bench_ecdh_batch） | 49.4 µs | 49.3 µs | ≈持平 |
| ECDH 批量 16 条/块 | 41.2 µs | 41.0 µs | ≈持平 |
| ECDSA verify（固定签名微基准） | 57.6 µs | 58.5 µs | +1.5% |
| ECDSA keygen / sign | 14.9 / 22.2 µs | 14.8 / 22.0 µs | ≈持平 |

**结论**：吞吐在标准基准上基本持平；真实随机密钥场景略快（−9%），固定密钥微基准略慢（+15%）——
差异只取决于分支预测器能否学会当前密钥的模式（真实 TLS 每握手都是新密钥，学不会）。
主要收益是**常数时间**：点运算不再有密钥相关的条件跳转，keygen/sign（已用 CT comb）成为整体常数时间，
消除了一类时序侧信道。P-384/P-521 走 C++ 点运算（`mod_add/mod_sub` 仍有分支），不受此改动影响。

**剩余的单次提速空间**：1) 求逆加法链/汇编（mod_inv p 现 4.5 µs，2 次/操作 ≈ 9 µs，专用链可省 3-4 µs）；
2) 点运算主循环进一步去栈往返/提升 ILP（wNAF 31 µs，理论域乘下限 ~23 µs）；3) 固定窗口 CT 查表
（实测 `ct_fixed_window` 因 select 开销反慢，需先优化 select 才有意义）。

### Phase 3.2：P-256 专用求逆加法链 + 汇编（已实现）

完成上一节剩余空间第 1 项：`mod_inv p` 从通用 Fermat（256 sq + 128 mul，4.27 µs）换成
addchain 专用链 **255 sq + 12 mul**（与 Go `crypto/internal/nistec/fiat/p256_invert.go`
同源，addchain v0.4.0 生成，指数 p−2）。

**实现**：`src/ecdsa_p256_adx.asm` 新增 `jpssl_p256_inv_adx(rcx=r, rdx=a)`，栈上放 14 个
4-limb 临时变量，267 步全部调用现有 `jpssl_p256_mul_adx`（输出已完全归约，无需额外约减）；
开头把输入复制到栈上，允许 r==a 别名；0 输入自然得到 0（与 mont_pow 语义一致）。
`mod_inv` 分发：仅 `N==4 && M.special==1 && g_p256_adx_ok` 走新路径；P-256 阶 n
（special==2，ECDSA 签名用）与 P-384/P-521 仍走通用 Fermat。

**验证**：20k 随机值与 `mont_pow`（同一 mul_adx 后端）对拍全过；性质 `mont_mul(a, inv(a))==R`
全过；边界 inv(1)、inv(mont 1)、inv(p−1)、inv(2)、inv(0)、r==a 别名全过；test_ecdsa 19 项、
test_tls 156 项全过。常数时间：整条链为固定指令序列、无数据相关分支。

实测（i7-13700K，MSVC Release，同进程 A/B）：

| 指标 | Fermat（旧） | addchain（新） | 变化 |
| --- | --- | --- | --- |
| mod_inv p（直接调用） | 4.27 µs | 2.89 µs | −32%（1.47×） |
| ECDH per-op 固定密钥 | 48.7 µs | 46.7 µs | −2 µs |
| ECDH per-op 批量 16 | 41.0 µs | 41.2 µs | ≈持平（噪声） |

求逆理论下限约 2.3 µs（267 × 8.7 ns 域乘）；差距来自每次 mul_adx 的 call/push/pop 开销，
后续可做"轻量 mul"（免寄存器保存）或把链内平方内联到主循环。

### Phase 3.3：合并上游后的 flaky 堆损坏排查（已解决）

合并上游 TLS socket 增强（9d88f7e）后 `test_tls_socket` 约 50% 概率堆损坏崩溃（0xC0000374）。
排查结论有两层：

1. **代码层根因**（`include/tls_socket.hpp` 的 `tls_co_task`）：`await_resume()` 销毁内层
   协程帧后未把 `h_` 置空；`co_await 嵌套任务(...)` 全表达式结束时临时任务对象析构会再次
   `destroy()` 同一帧 → double-free。修复：销毁后 `h_ = nullptr`（模板与 void 特化两处）。
   用最小无 socket 复现（`scratch_co_task_probe`，纯嵌套 co_await 20 万次）验证修复语义。
2. **构建层陷阱**：ninja 的依赖跟踪在合并/改头文件后没有重编 `tls_socket.cpp.obj`（同样曾导致
   `test_tls.cpp.obj` 按旧 `tls_session` 布局编译），旧协程代码与新头文件混链 → 修复"看似无效"。
   `ninja -t clean` 全量重建后，`test_tls_socket` 连续 43 次全过，`test_ecdsa`/`test_tls` 全过。
   若后续改头文件出现"没重编"现象，优先怀疑依赖跟踪（需要 clean 重建或检查 ninja deps）。

## 7. 参考资料

- Bellare, Garay, Rabin: [Fast Batch Verification for Modular Exponentiation and Digital Signatures](https://dblp2.uni-trier.de/rec/journals/iacr/BellareGR98.html)（批量验证理论，小指数测试）
- Gueron, Krasnov: [Fast prime field elliptic-curve cryptography with 256-bit primes](https://link.springer.com/article/10.1007/s13389-014-0090-x)（P-256，定点乘窗口 7 + AVX2 并行 4 点加，J. Cryptogr. Eng. 5(2), 2015）
- Huang, Liu, Hu, Großschädl: [Parallel Implementation of SM2 Elliptic Curve Cryptography on Intel Processors with AVX2](https://junhaohuang.github.io/assets/paper/ACISP2020.pdf)（ACISP 2020：radix-2^26 2-way AVX2 字段算术，Co-Z 阶梯 1.31×，抗时序）
- Intel IPP Crypto：Multi-buffer Cryptography（[mbx_nistp256_ecdsa_sign](https://www.intel.com/content/www/us/en/docs/crypto-primitives-library/developer-guide-reference/2025-0/mbx-nistp256-384-521-ecdsa-sign.html)，[IPP-Crypto 源码](https://github.com/intel/ipp-crypto)）
- curve25519-dalek: [AVX512-IFMA 笔记](https://github.com/dalek-cryptography/curve25519-dalek/blob/3.1.0/docs/ifma-notes.md)（radix-2^52/2^51 乘法的完整推导）
- asmcrypto: [AVX-512 批量 ECDSA 恢复基准](https://docs.rs/asmcrypto/latest/asmcrypto/)（8-lane，约 15.6 µs/lane，Zen 5）
- OpenJDK: [P-256 Montgomery 乘 AVX2 内建函数（约 60–80% 提升）](https://bugs.openjdk.org/browse/JDK-8353670)
- OpenSSL: [移除 ecp_nistz256 中不可达的 AVX2 代码（PR #12046）](https://github.com/openssl/openssl/pull/12046)
