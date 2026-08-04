; sm3_win.asm - SM3 压缩函数标量汇编 (Windows x64, MASM/ml64)
;
; 调用约定: Microsoft x64
;   sm3_compress_asm(rcx = uint32_t h[8], rdx = const uint8_t block[64])
;
; 与 src/sm3.cpp 的 C 标量版 sm3_cf 等价:
;   - 消息扩展 W[16..67] 与 64 轮压缩全部展开, 无分支/无循环;
;   - 状态 A..H 用寄存器轮换, 旋转用单条 rol 指令 (C 版是 移位+或);
;   - block 大端 bswap 载入, 省掉 C 侧 load_be32 循环.
;
; 寄存器分配:
;   r8d..r15d           : 状态 A..H
;   eax,ebx,ecx,edx,esi,edi : 临时
;   rbp                 : W[] 栈基址, W[j] = dword ptr [rbp + 4*j]
;   [rbp + 272]         : 保存 h 指针
;
; 轮常量 K_j = ROTL(T_{j/16}, j & 31), 与 Linux 内核
; arch/x86/crypto/sm3-avx-asm_64.S 中的 K0..K63 一致.

.code

; ---- 消息扩展:
;   W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j-13],7) ^ W[j-6]
;   P1(X) = X ^ ROTL(X,15) ^ ROTL(X,23)
EXPAND MACRO J
    mov  eax, dword ptr [rbp + 4*(J-3)]
    rol  eax, 15
    xor  eax, dword ptr [rbp + 4*(J-16)]
    xor  eax, dword ptr [rbp + 4*(J-9)]
    mov  ebx, eax
    mov  ecx, eax
    rol  eax, 15
    rol  ecx, 23
    xor  eax, ecx
    xor  eax, ebx
    mov  edx, dword ptr [rbp + 4*(J-13)]
    rol  edx, 7
    xor  eax, edx
    xor  eax, dword ptr [rbp + 4*(J-6)]
    mov  dword ptr [rbp + 4*J], eax
ENDM

; ---- 压缩轮 0..15: FF0 = x^y^z, GG0 = x^y^z
ROUND0 MACRO J, K
    mov  edi, dword ptr [rbp + 4*J]
    mov  esi, dword ptr [rbp + 4*J + 16]
    xor  esi, edi
    mov  ebx, r8d
    rol  ebx, 12
    mov  eax, ebx
    add  eax, r12d
    add  eax, K
    rol  eax, 7
    xor  ebx, eax
    mov  ecx, r8d
    xor  ecx, r9d
    xor  ecx, r10d
    add  ecx, r11d
    add  ecx, ebx
    add  ecx, esi
    mov  edx, r9d
    rol  edx, 9
    mov  r11d, r10d
    mov  r10d, edx
    mov  r9d, r8d
    mov  r8d, ecx
    mov  ecx, r12d
    xor  ecx, r13d
    xor  ecx, r14d
    add  ecx, r15d
    add  ecx, eax
    add  ecx, edi
    mov  edi, ecx
    rol  ecx, 9
    xor  ecx, edi
    rol  edi, 17
    xor  ecx, edi
    mov  edi, r13d
    rol  edi, 19
    mov  r15d, r14d
    mov  r14d, edi
    mov  r13d, r12d
    mov  r12d, ecx
ENDM

; ---- 压缩轮 16..63: FF1 = (x&y)|(x&z)|(y&z), GG1 = (x&y)|(~x&z)
ROUND1 MACRO J, K
    mov  edi, dword ptr [rbp + 4*J]
    mov  esi, dword ptr [rbp + 4*J + 16]
    xor  esi, edi
    mov  ebx, r8d
    rol  ebx, 12
    mov  eax, ebx
    add  eax, r12d
    add  eax, K
    rol  eax, 7
    xor  ebx, eax
    mov  ecx, r8d
    and  ecx, r9d
    mov  edx, r8d
    and  edx, r10d
    or   ecx, edx
    mov  edx, r9d
    and  edx, r10d
    or   ecx, edx
    add  ecx, r11d
    add  ecx, ebx
    add  ecx, esi
    mov  edx, r9d
    rol  edx, 9
    mov  r11d, r10d
    mov  r10d, edx
    mov  r9d, r8d
    mov  r8d, ecx
    mov  ecx, r12d
    and  ecx, r13d
    mov  edx, r12d
    not  edx
    and  edx, r14d
    or   ecx, edx
    add  ecx, r15d
    add  ecx, eax
    add  ecx, edi
    mov  edi, ecx
    rol  ecx, 9
    xor  ecx, edi
    rol  edi, 17
    xor  ecx, edi
    mov  edi, r13d
    rol  edi, 19
    mov  r15d, r14d
    mov  r14d, edi
    mov  r13d, r12d
    mov  r12d, ecx
ENDM

sm3_compress_asm PROC
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 288                 ; W[0..67]=272B + h 指针 8B + 对齐
    mov  rbp, rsp
    mov  qword ptr [rbp + 272], rcx   ; 保存 h 指针

    ; ---- 载入 W[0..15]: 大端 -> 小端 ----
    mov  eax, dword ptr [rdx]
    bswap eax
    mov  dword ptr [rbp], eax
    mov  eax, dword ptr [rdx + 4]
    bswap eax
    mov  dword ptr [rbp + 4], eax
    mov  eax, dword ptr [rdx + 8]
    bswap eax
    mov  dword ptr [rbp + 8], eax
    mov  eax, dword ptr [rdx + 12]
    bswap eax
    mov  dword ptr [rbp + 12], eax
    mov  eax, dword ptr [rdx + 16]
    bswap eax
    mov  dword ptr [rbp + 16], eax
    mov  eax, dword ptr [rdx + 20]
    bswap eax
    mov  dword ptr [rbp + 20], eax
    mov  eax, dword ptr [rdx + 24]
    bswap eax
    mov  dword ptr [rbp + 24], eax
    mov  eax, dword ptr [rdx + 28]
    bswap eax
    mov  dword ptr [rbp + 28], eax
    mov  eax, dword ptr [rdx + 32]
    bswap eax
    mov  dword ptr [rbp + 32], eax
    mov  eax, dword ptr [rdx + 36]
    bswap eax
    mov  dword ptr [rbp + 36], eax
    mov  eax, dword ptr [rdx + 40]
    bswap eax
    mov  dword ptr [rbp + 40], eax
    mov  eax, dword ptr [rdx + 44]
    bswap eax
    mov  dword ptr [rbp + 44], eax
    mov  eax, dword ptr [rdx + 48]
    bswap eax
    mov  dword ptr [rbp + 48], eax
    mov  eax, dword ptr [rdx + 52]
    bswap eax
    mov  dword ptr [rbp + 52], eax
    mov  eax, dword ptr [rdx + 56]
    bswap eax
    mov  dword ptr [rbp + 56], eax
    mov  eax, dword ptr [rdx + 60]
    bswap eax
    mov  dword ptr [rbp + 60], eax

    ; ---- 消息扩展 W[16..67] ----
    EXPAND 16
    EXPAND 17
    EXPAND 18
    EXPAND 19
    EXPAND 20
    EXPAND 21
    EXPAND 22
    EXPAND 23
    EXPAND 24
    EXPAND 25
    EXPAND 26
    EXPAND 27
    EXPAND 28
    EXPAND 29
    EXPAND 30
    EXPAND 31
    EXPAND 32
    EXPAND 33
    EXPAND 34
    EXPAND 35
    EXPAND 36
    EXPAND 37
    EXPAND 38
    EXPAND 39
    EXPAND 40
    EXPAND 41
    EXPAND 42
    EXPAND 43
    EXPAND 44
    EXPAND 45
    EXPAND 46
    EXPAND 47
    EXPAND 48
    EXPAND 49
    EXPAND 50
    EXPAND 51
    EXPAND 52
    EXPAND 53
    EXPAND 54
    EXPAND 55
    EXPAND 56
    EXPAND 57
    EXPAND 58
    EXPAND 59
    EXPAND 60
    EXPAND 61
    EXPAND 62
    EXPAND 63
    EXPAND 64
    EXPAND 65
    EXPAND 66
    EXPAND 67

    ; ---- 载入状态 A..H ----
    mov  rcx, qword ptr [rbp + 272]
    mov  r8d, dword ptr [rcx]
    mov  r9d, dword ptr [rcx + 4]
    mov  r10d, dword ptr [rcx + 8]
    mov  r11d, dword ptr [rcx + 12]
    mov  r12d, dword ptr [rcx + 16]
    mov  r13d, dword ptr [rcx + 20]
    mov  r14d, dword ptr [rcx + 24]
    mov  r15d, dword ptr [rcx + 28]

    ; ---- 压缩轮 0..15 ----
    ROUND0 0, 079cc4519h
    ROUND0 1, 0f3988a32h
    ROUND0 2, 0e7311465h
    ROUND0 3, 0ce6228cbh
    ROUND0 4, 09cc45197h
    ROUND0 5, 03988a32fh
    ROUND0 6, 07311465eh
    ROUND0 7, 0e6228cbch
    ROUND0 8, 0cc451979h
    ROUND0 9, 0988a32f3h
    ROUND0 10, 0311465e7h
    ROUND0 11, 06228cbceh
    ROUND0 12, 0c451979ch
    ROUND0 13, 088a32f39h
    ROUND0 14, 011465e73h
    ROUND0 15, 0228cbce6h

    ; ---- 压缩轮 16..63 ----
    ROUND1 16, 09d8a7a87h
    ROUND1 17, 03b14f50fh
    ROUND1 18, 07629ea1eh
    ROUND1 19, 0ec53d43ch
    ROUND1 20, 0d8a7a879h
    ROUND1 21, 0b14f50f3h
    ROUND1 22, 0629ea1e7h
    ROUND1 23, 0c53d43ceh
    ROUND1 24, 08a7a879dh
    ROUND1 25, 014f50f3bh
    ROUND1 26, 029ea1e76h
    ROUND1 27, 053d43cech
    ROUND1 28, 0a7a879d8h
    ROUND1 29, 04f50f3b1h
    ROUND1 30, 09ea1e762h
    ROUND1 31, 03d43cec5h
    ROUND1 32, 07a879d8ah
    ROUND1 33, 0f50f3b14h
    ROUND1 34, 0ea1e7629h
    ROUND1 35, 0d43cec53h
    ROUND1 36, 0a879d8a7h
    ROUND1 37, 050f3b14fh
    ROUND1 38, 0a1e7629eh
    ROUND1 39, 043cec53dh
    ROUND1 40, 0879d8a7ah
    ROUND1 41, 00f3b14f5h
    ROUND1 42, 01e7629eah
    ROUND1 43, 03cec53d4h
    ROUND1 44, 079d8a7a8h
    ROUND1 45, 0f3b14f50h
    ROUND1 46, 0e7629ea1h
    ROUND1 47, 0cec53d43h
    ROUND1 48, 09d8a7a87h
    ROUND1 49, 03b14f50fh
    ROUND1 50, 07629ea1eh
    ROUND1 51, 0ec53d43ch
    ROUND1 52, 0d8a7a879h
    ROUND1 53, 0b14f50f3h
    ROUND1 54, 0629ea1e7h
    ROUND1 55, 0c53d43ceh
    ROUND1 56, 08a7a879dh
    ROUND1 57, 014f50f3bh
    ROUND1 58, 029ea1e76h
    ROUND1 59, 053d43cech
    ROUND1 60, 0a7a879d8h
    ROUND1 61, 04f50f3b1h
    ROUND1 62, 09ea1e762h
    ROUND1 63, 03d43cec5h

    ; ---- 更新 h[i] ^= 状态 ----
    mov  rcx, qword ptr [rbp + 272]
    mov  eax, dword ptr [rcx]
    xor  eax, r8d
    mov  dword ptr [rcx], eax
    mov  eax, dword ptr [rcx + 4]
    xor  eax, r9d
    mov  dword ptr [rcx + 4], eax
    mov  eax, dword ptr [rcx + 8]
    xor  eax, r10d
    mov  dword ptr [rcx + 8], eax
    mov  eax, dword ptr [rcx + 12]
    xor  eax, r11d
    mov  dword ptr [rcx + 12], eax
    mov  eax, dword ptr [rcx + 16]
    xor  eax, r12d
    mov  dword ptr [rcx + 16], eax
    mov  eax, dword ptr [rcx + 20]
    xor  eax, r13d
    mov  dword ptr [rcx + 20], eax
    mov  eax, dword ptr [rcx + 24]
    xor  eax, r14d
    mov  dword ptr [rcx + 24], eax
    mov  eax, dword ptr [rcx + 28]
    xor  eax, r15d
    mov  dword ptr [rcx + 28], eax

    add  rsp, 288
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    pop  rbp
    ret
sm3_compress_asm ENDP

END
