; ecdsa_p256_adx.asm - Windows x64 (masm/ml64) P-256 Montgomery 閸╃喍绠诲▔?;
;   jpssl_p256_mul_adx(rcx=r, rdx=a, r8=b)   (extern "C")
;
; 鐠侊紕鐣?r = a*b*R^{-1} mod p, R = 2^256,
; p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
; 閿涘牐绶崗?a,b 閸?< p閿涘矁绶崙?r < p閿?;
; 缂佹挻鐎弶銉ㄥ殰 OpenSSL ecp_nistz256-x86_64.pl 閻?__ecp_nistz256_mul_montx
; 閿涘牅姘﹂柨?CIOS + p 閻ㄥ嫮澹掑▓濠傝埌瀵繐缍婄痪锔肩礉MULX/SHLX/SHRX + ADCX/ADOX 閸欏矁绻樻担宥夋懠閿涘绱?; 閹?Windows x64 鐎靛嫬鐡ㄩ崳銊╁櫢閺勭姴鐨犻妴?;
; 鐎靛嫬鐡ㄩ崳銊︽Ё鐏忓嫸绱橶indows x64閿?
;   rdi=r_ptr, rsi=a_ptr, rbx=b_ptr
;   acc0..acc5 = r8..r13 ; t0=rcx, t1=rbp, t2=rbx(婢跺秶鏁?, t3=rdx, t4=rax
;   poly1=r14閿涘牆鍘涙担婊呅╂担宥堫吀閺?32閿涘本娓堕崥搴濈稊 p 鐎?1閿? poly3=r15 (=0xffffffff00000001)
;
; MASM 閻?MULX 閹垮秳缍旈弫浼淬€庢惔蹇庤礋 (hi, lo, src)閿涘牅绗?AT&T 閻╃寮介敍澶堚偓?
.code

jpssl_p256_mul_adx PROC
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    mov     rdi, rcx                    ; r_ptr = res
    mov     rsi, rdx                    ; a_ptr = a
    mov     rbx, r8                     ; b_ptr = b

    ; ---- 鏉炶棄鍙?a[0..3] -> acc1..acc4 ----
    mov     r9,  qword ptr [rsi]        ; acc1 = a[0]
    mov     r10, qword ptr [rsi+8]      ; acc2 = a[1]
    mov     r11, qword ptr [rsi+16]     ; acc3 = a[2]
    mov     r12, qword ptr [rsi+24]     ; acc4 = a[3]

    ; ---- Multiply by b[0] ----
    mov     rdx, qword ptr [rbx]        ; rdx = b[0]
    mulx    r9, r8, r9                  ; b0*a0: hi=acc1, lo=acc0
    mulx    r10, rcx, r10               ; b0*a1: hi=acc2, lo=t0
    mov     r14, 32                     ; poly1 = 缁夎缍呯拋鈩冩殶
    xor     r13, r13
    mulx    r11, rbp, r11               ; b0*a2: hi=acc3, lo=t1
    mov     r15, 0ffffffff00000001h     ; poly3
    adc     r9, rcx                     ; acc1 += t0
    mulx    r12, rcx, r12               ; b0*a3: hi=acc4, lo=t0
    mov     rdx, r8                     ; rdx = acc0
    adc     r10, rbp                    ; acc2 += t1
    shlx    rbp, r8, r14                ; t1 = acc0 << 32
    adc     r11, rcx                    ; acc3 += t0
    shrx    rcx, r8, r14                ; t0 = acc0 >> 32
    adc     r12, 0                      ; acc4 += carry

    ; ---- First reduction step ----
    add     r9, rbp                     ; acc1 += acc0<<32
    adc     r10, rcx                    ; acc2 += acc0>>32
    mulx    rbp, rcx, r15               ; acc0 * poly3: hi=t1, lo=t0
    mov     rdx, qword ptr [rbx+8]      ; rdx = b[1]
    adc     r11, rcx                    ; acc3 += t0
    adc     r12, rbp                    ; acc4 += t1
    adc     r13, 0                      ; acc5 += carry
    xor     r8, r8                      ; acc0 = 0閿涘湑F=0, OF=0閿?
    ; ---- Multiply by b[1] ----
    mulx    rbp, rcx, qword ptr [rsi]   ; b1*a0: hi=t1, lo=t0
    adcx    r9, rcx                     ; acc1 += t0
    adox    r10, rbp                    ; acc2 += t1
    mulx    rbp, rcx, qword ptr [rsi+8] ; b1*a1
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, qword ptr [rsi+16]; b1*a2
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [rsi+24]; b1*a3
    mov     rdx, r9                     ; rdx = acc1
    adcx    r12, rcx
    shlx    rcx, r9, r14                ; t0 = acc1 << 32
    adox    r13, rbp
    shrx    rbp, r9, r14                ; t1 = acc1 >> 32
    adcx    r13, r8                     ; acc5 += acc0
    adox    r8, r8
    adc     r8, 0                       ; acc0 = 鏉╂稐缍?
    ; ---- Second reduction step ----
    add     r10, rcx                    ; acc2 += acc1<<32
    adc     r11, rbp                    ; acc3 += acc1>>32
    mulx    rbp, rcx, r15               ; acc1 * poly3: hi=t1, lo=t0
    mov     rdx, qword ptr [rbx+16]     ; rdx = b[2]
    adc     r12, rcx                    ; acc4 += t0
    adc     r13, rbp                    ; acc5 += t1
    adc     r8, 0                       ; acc0 += carry
    xor     r9, r9                      ; acc1 = 0閿涘湑F=0, OF=0閿?
    ; ---- Multiply by b[2] ----
    mulx    rbp, rcx, qword ptr [rsi]   ; b2*a0
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, qword ptr [rsi+8] ; b2*a1
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [rsi+16]; b2*a2
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, qword ptr [rsi+24]; b2*a3
    mov     rdx, r10                    ; rdx = acc2
    adcx    r13, rcx
    shlx    rcx, r10, r14               ; t0 = acc2 << 32
    adox    r8, rbp                     ; acc0 += t1
    shrx    rbp, r10, r14               ; t1 = acc2 >> 32
    adcx    r8, r9                      ; acc0 += acc1
    adox    r9, r9
    adc     r9, 0                       ; acc1 = 鏉╂稐缍?
    ; ---- Third reduction step ----
    add     r11, rcx                    ; acc3 += acc2<<32
    adc     r12, rbp                    ; acc4 += acc2>>32
    mulx    rbp, rcx, r15               ; acc2 * poly3: hi=t1, lo=t0
    mov     rdx, qword ptr [rbx+24]     ; rdx = b[3]
    adc     r13, rcx                    ; acc5 += t0
    adc     r8, rbp                     ; acc0 += t1
    adc     r9, 0                       ; acc1 += carry
    xor     r10, r10                    ; acc2 = 0閿涘湑F=0, OF=0閿?
    ; ---- Multiply by b[3] ----
    mulx    rbp, rcx, qword ptr [rsi]   ; b3*a0
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [rsi+8] ; b3*a1
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, qword ptr [rsi+16]; b3*a2
    adcx    r13, rcx
    adox    r8, rbp
    mulx    rbp, rcx, qword ptr [rsi+24]; b3*a3
    mov     rdx, r11                    ; rdx = acc3
    adcx    r8, rcx
    shlx    rcx, r11, r14               ; t0 = acc3 << 32
    adox    r9, rbp                     ; acc1 += t1
    shrx    rbp, r11, r14               ; t1 = acc3 >> 32
    adcx    r9, r10                     ; acc1 += acc2
    adox    r10, r10
    adc     r10, 0                      ; acc2 = 鏉╂稐缍?
    ; ---- Fourth reduction step ----
    add     r12, rcx                    ; acc4 += acc3<<32
    adc     r13, rbp                    ; acc5 += acc3>>32
    mulx    rbp, rcx, r15               ; acc3 * poly3: hi=t1, lo=t0
    mov     rbx, r12                    ; t2 = acc4閿涘牅绻氱€涙ê甯崐纭风礆
    mov     r14, 0ffffffffh             ; poly1 = p 鐎?1
    adc     r8, rcx                     ; acc0 += t0
    mov     rdx, r13                    ; t3 = acc5閿涘牅绻氱€涙ê甯崐纭风礆
    adc     r9, rbp                     ; acc1 += t1
    adc     r10, 0                      ; acc2 += carry

    ; ---- Branch-less conditional subtraction of P ----
    xor     eax, eax                    ; CF=0
    mov     rcx, r8                     ; t0 = acc0閿涘牅绻氱€涙ê甯崐纭风礆
    sbb     r12, -1                     ; acc4 -= poly[0] (=-1)
    sbb     r13, r14                    ; acc5 -= poly1
    sbb     r8, 0
    mov     rbp, r9                     ; t1 = acc1閿涘牅绻氱€涙ê甯崐纭风礆
    sbb     r9, r15                     ; acc1 -= poly3
    sbb     r10, 0                      ; acc2 -= 0閿涘牆鈧喍缍呴崙鐚寸礆

    cmovc   r12, rbx                    ; 閸婄喍缍呴崚娆愪划婢?acc4
    cmovc   r13, rdx                    ; 閹垹顦?acc5
    mov     qword ptr [rdi], r12
    cmovc   r8, rcx                     ; 閹垹顦?acc0
    mov     qword ptr [rdi+8], r13
    cmovc   r9, rbp                     ; 閹垹顦?acc1
    mov     qword ptr [rdi+16], r8
    mov     qword ptr [rdi+24], r9

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_mul_adx ENDP

.data
; 缂囥倝妯?n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
ord_n QWORD 0f3b9cac2fc632551h, 0bce6faada7179e84h, 0ffffffffffffffffh, 0ffffffff00000000h

.code

; jpssl_p256_ord_mul_adx(rcx=r, rdx=a, r8=b): r = a*b*R^{-1} mod n
jpssl_p256_ord_mul_adx PROC
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    mov     rdi, rcx                    ; r_ptr
    mov     rsi, rdx                    ; a_ptr
    mov     rbx, r8                     ; b_ptr
    lea     r14, ord_n
    mov     r15, 0ccd1c8aaee00bc4fh     ; r15 = LordK

    mov     r9,  qword ptr [rsi]        ; acc1 = a[0]
    mov     r10, qword ptr [rsi+8]      ; acc2 = a[1]
    mov     r11, qword ptr [rsi+16]     ; acc3 = a[2]
    mov     r12, qword ptr [rsi+24]     ; acc4 = a[3]

    ; ---- Multiply by b[0] ----
    mov     rdx, qword ptr [rbx]        ; rdx = b[0]
    mulx    r9, r8, r9                  ; b0*a0: hi=acc1, lo=acc0
    mulx    r10, rcx, r10               ; b0*a1: hi=acc2, lo=t0
    mulx    r11, rbp, r11               ; b0*a2: hi=acc3, lo=t1
    add     r9, rcx                     ; acc1 += t0
    mulx    r12, rcx, r12               ; b0*a3: hi=acc4, lo=t0
    mov     rdx, r8                     ; rdx = acc0
    mulx    rax, rdx, r15               ; u = acc0*K0 (lo=rdx)
    adc     r10, rbp                    ; acc2 += t1
    adc     r11, rcx                    ; acc3 += t0
    adc     r12, 0                      ; acc4 += carry

    ; ---- reduction ----
    xor     r13, r13                    ; acc5 = 0 (cf=0, of=0)
    mulx    rbp, rcx, qword ptr [r14]   ; u*n0: hi=t1, lo=t0
    adcx    r8, rcx
    adox    r9, rbp                     ; acc1 += hi
    mulx    rbp, rcx, qword ptr [r14+8] ; u*n1
    adcx    r9, rcx
    adox    r10, rbp
    mulx    rbp, rcx, qword ptr [r14+16]; u*n2
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, qword ptr [r14+24]; u*n3
    mov     rdx, qword ptr [rbx+8]      ; rdx = b[1]
    adcx    r11, rcx
    adox    r12, rbp
    adcx    r12, r8                     ; acc4 += acc0
    adox    r13, r8                     ; acc5 += acc0
    adc     r13, 0                      ; acc5 += carry閿涘潏f=0, of=0閿?
    ; ---- Multiply by b[1] ----
    mulx    rbp, rcx, qword ptr [rsi]   ; b1*a0
    adcx    r9, rcx
    adox    r10, rbp
    mulx    rbp, rcx, qword ptr [rsi+8] ; b1*a1
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, qword ptr [rsi+16]; b1*a2
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [rsi+24]; b1*a3
    mov     rdx, r9                     ; rdx = acc1
    mulx    rax, rdx, r15               ; u = acc1*K0
    adcx    r12, rcx
    adox    r13, rbp
    adcx    r13, r8                     ; acc5 += acc0
    adox    r8, r8
    adc     r8, 0                       ; acc0 = 鏉╂稐缍呴敍鍧坒=0, of=0閿?
    ; ---- reduction ----
    mulx    rbp, rcx, qword ptr [r14]   ; u*n0
    adcx    r9, rcx
    adox    r10, rbp
    mulx    rbp, rcx, qword ptr [r14+8]
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, qword ptr [r14+16]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [r14+24]
    mov     rdx, qword ptr [rbx+16]     ; rdx = b[2]
    adcx    r12, rcx
    adox    r13, rbp
    adcx    r13, r9                     ; acc5 += acc1
    adox    r8, r9
    adc     r8, 0                       ; acc0 = 鏉╂稐缍?
    ; ---- Multiply by b[2] ----
    mulx    rbp, rcx, qword ptr [rsi]
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, qword ptr [rsi+8]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [rsi+16]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, qword ptr [rsi+24]
    mov     rdx, r10                    ; rdx = acc2
    mulx    rax, rdx, r15               ; u = acc2*K0
    adcx    r13, rcx
    adox    r8, rbp                     ; acc0 += hi
    adcx    r8, r9                      ; acc0 += acc1
    adox    r9, r9
    adc     r9, 0                       ; acc1 = 鏉╂稐缍?
    ; ---- reduction ----
    mulx    rbp, rcx, qword ptr [r14]
    adcx    r10, rcx
    adox    r11, rbp
    mulx    rbp, rcx, qword ptr [r14+8]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [r14+16]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, qword ptr [r14+24]
    mov     rdx, qword ptr [rbx+24]     ; rdx = b[3]
    adcx    r13, rcx
    adox    r8, rbp
    adcx    r8, r10                     ; acc0 += acc2
    adox    r9, r10
    adc     r9, 0                       ; acc1 = 鏉╂稐缍?
    ; ---- Multiply by b[3] ----
    mulx    rbp, rcx, qword ptr [rsi]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [rsi+8]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, qword ptr [rsi+16]
    adcx    r13, rcx
    adox    r8, rbp
    mulx    rbp, rcx, qword ptr [rsi+24]
    mov     rdx, r11                    ; rdx = acc3
    mulx    rax, rdx, r15               ; u = acc3*K0
    adcx    r8, rcx
    adox    r9, rbp
    adcx    r9, r10                     ; acc1 += acc2
    adox    r10, r10
    adc     r10, 0                      ; acc2 = 鏉╂稐缍?
    ; ---- reduction ----
    mulx    rbp, rcx, qword ptr [r14]
    adcx    r11, rcx
    adox    r12, rbp
    mulx    rbp, rcx, qword ptr [r14+8]
    adcx    r12, rcx
    adox    r13, rbp
    mulx    rbp, rcx, qword ptr [r14+16]
    adcx    r13, rcx
    adox    r8, rbp
    mulx    rbp, rcx, qword ptr [r14+24]
    mov     rbx, r12                    ; t2 = acc4閿涘牅绻氱€涙ê甯崐纭风礆
    adcx    r8, rcx
    adox    r9, rbp
    mov     rdx, r13                    ; t3 = acc5閿涘牅绻氱€涙ê甯崐纭风礆
    adcx    r9, r11                     ; acc1 += acc3
    adox    r10, r11
    adc     r10, 0                      ; acc2 = 鏉╂稐缍?
    ; ---- Branch-less conditional subtraction of n ----
    mov     rcx, r8                     ; t0 = acc0閿涘牅绻氱€涙ê甯崐纭风礆
    sub     r12, qword ptr [r14]        ; acc4 -= n[0]
    sbb     r13, qword ptr [r14+8]      ; acc5 -= n[1]
    sbb     r8, qword ptr [r14+16]      ; acc0 -= n[2]
    mov     rbp, r9                     ; t1 = acc1閿涘牅绻氱€涙ê甯崐纭风礆
    sbb     r9, qword ptr [r14+24]      ; acc1 -= n[3]
    sbb     r10, 0                      ; acc2 -= 0閿涘牆鈧喍缍呴崙鐚寸礆

    cmovc   r12, rbx
    cmovc   r13, rdx
    mov     qword ptr [rdi], r12
    cmovc   r8, rcx
    mov     qword ptr [rdi+8], r13
    cmovc   r9, rbp
    mov     qword ptr [rdi+16], r8
    mov     qword ptr [rdi+24], r9

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_ord_mul_adx ENDP

.data
field_p QWORD 0ffffffffffffffffh, 0ffffffffh, 0, 0ffffffff00000001h
field_one QWORD 0000000000000001h, 0ffffffffh, 0ffffffffffffffffh, 00000000fffffffeh

.code

jpssl_p256_dbl PROC
X      EQU 0
Y      EQU 32
Z      EQU 64
A      EQU 96
B      EQU 128
C      EQU 160
D      EQU 192
E      EQU 224
T      EQU 256
X3     EQU 288
Y3     EQU 320
Z3     EQU 352

    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, 384

    mov     rdi, rcx                    ; rdi = r
    mov     rsi, rdx                    ; rsi = p
    mov     r15, 0ffffffff00000001h     ; p word 3 (kept across calls)
    mov     r14, 0ffffffffh             ; p word 1 = 0x00000000ffffffff (zero-extended)

    ; 鏉炶棄鍙?X, Y, Z
    mov     rax, [rsi]
    mov     rcx, [rsi+8]
    mov     rdx, [rsi+16]
    mov     r8, [rsi+24]
    mov     [rsp+X], rax
    mov     [rsp+X+8], rcx
    mov     [rsp+X+16], rdx
    mov     [rsp+X+24], r8
    mov     rax, [rsi+32]
    mov     rcx, [rsi+40]
    mov     rdx, [rsi+48]
    mov     r8, [rsi+56]
    mov     [rsp+Y], rax
    mov     [rsp+Y+8], rcx
    mov     [rsp+Y+16], rdx
    mov     [rsp+Y+24], r8
    mov     rax, [rsi+64]
    mov     rcx, [rsi+72]
    mov     rdx, [rsi+80]
    mov     r8, [rsi+88]
    mov     [rsp+Z], rax
    mov     [rsp+Z+8], rcx
    mov     [rsp+Z+16], rdx
    mov     [rsp+Z+24], r8

    ; A = X^2
    lea     rcx, [rsp+A]
    lea     rdx, [rsp+X]
    call    jpssl_p256_sqr_adx
    ; B = Y^2
    lea     rcx, [rsp+B]
    lea     rdx, [rsp+Y]
    call    jpssl_p256_sqr_adx
    ; C = B^2
    lea     rcx, [rsp+C]
    lea     rdx, [rsp+B]
    call    jpssl_p256_sqr_adx
    ; T = X + B
    mov     rax, [rsp+X]
    mov     rcx, [rsp+X+8]
    mov     rdx, [rsp+X+16]
    mov     r8, [rsp+X+24]
    add     rax, [rsp+B]
    adc     rcx, [rsp+B+8]
    adc     rdx, [rsp+B+16]
    adc     r8, [rsp+B+24]
    setc    r9b
    movzx   r9d, r9b                ; r9 = carry_out
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15                 ; rax..r8 = t; CF = borrow
    setc    r10b
    movzx   r10d, r10b              ; r10 = borrow
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+T], rax
    mov     [rsp+T+8], rcx
    mov     [rsp+T+16], rdx
    mov     [rsp+T+24], r8
    ; T = T^2
    lea     rcx, [rsp+T]
    lea     rdx, [rsp+T]
    call    jpssl_p256_sqr_adx
    ; T = T - A
    mov     rax, [rsp+T]
    mov     rcx, [rsp+T+8]
    mov     rdx, [rsp+T+16]
    mov     r8, [rsp+T+24]
    sub     rax, [rsp+A]
    sbb     rcx, [rsp+A+8]
    sbb     rdx, [rsp+A+16]
    sbb     r8, [rsp+A+24]
    setc    r13b
    movzx   r13d, r13b              ; r13 = borrow
    mov     r9, rax
    mov     r10, rcx
    mov     r11, rdx
    mov     r12, r8
    add     r9, -1
    adc     r10, r14
    adc     r11, 0
    adc     r12, r15                ; r9..r12 = a-b+p
    neg     r13                     ; CF = borrow
    cmovc   rax, r9
    cmovc   rcx, r10
    cmovc   rdx, r11
    cmovc   r8, r12
    mov     [rsp+T], rax
    mov     [rsp+T+8], rcx
    mov     [rsp+T+16], rdx
    mov     [rsp+T+24], r8
    ; T = T - C
    mov     rax, [rsp+T]
    mov     rcx, [rsp+T+8]
    mov     rdx, [rsp+T+16]
    mov     r8, [rsp+T+24]
    sub     rax, [rsp+C]
    sbb     rcx, [rsp+C+8]
    sbb     rdx, [rsp+C+16]
    sbb     r8, [rsp+C+24]
    setc    r13b
    movzx   r13d, r13b              ; r13 = borrow
    mov     r9, rax
    mov     r10, rcx
    mov     r11, rdx
    mov     r12, r8
    add     r9, -1
    adc     r10, r14
    adc     r11, 0
    adc     r12, r15                ; r9..r12 = a-b+p
    neg     r13                     ; CF = borrow
    cmovc   rax, r9
    cmovc   rcx, r10
    cmovc   rdx, r11
    cmovc   r8, r12
    mov     [rsp+T], rax
    mov     [rsp+T+8], rcx
    mov     [rsp+T+16], rdx
    mov     [rsp+T+24], r8
    ; D = T + T
    mov     rax, [rsp+T]
    mov     rcx, [rsp+T+8]
    mov     rdx, [rsp+T+16]
    mov     r8, [rsp+T+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+D], rax
    mov     [rsp+D+8], rcx
    mov     [rsp+D+16], rdx
    mov     [rsp+D+24], r8
    ; T = Z^2
    lea     rcx, [rsp+T]
    lea     rdx, [rsp+Z]
    call    jpssl_p256_sqr_adx
    ; T = T^2 (Z^4)
    lea     rcx, [rsp+T]
    lea     rdx, [rsp+T]
    call    jpssl_p256_sqr_adx
    ; T = A - T
    mov     rax, [rsp+A]
    mov     rcx, [rsp+A+8]
    mov     rdx, [rsp+A+16]
    mov     r8, [rsp+A+24]
    sub     rax, [rsp+T]
    sbb     rcx, [rsp+T+8]
    sbb     rdx, [rsp+T+16]
    sbb     r8, [rsp+T+24]
    setc    r13b
    movzx   r13d, r13b              ; r13 = borrow
    mov     r9, rax
    mov     r10, rcx
    mov     r11, rdx
    mov     r12, r8
    add     r9, -1
    adc     r10, r14
    adc     r11, 0
    adc     r12, r15                ; r9..r12 = a-b+p
    neg     r13                     ; CF = borrow
    cmovc   rax, r9
    cmovc   rcx, r10
    cmovc   rdx, r11
    cmovc   r8, r12
    mov     [rsp+T], rax
    mov     [rsp+T+8], rcx
    mov     [rsp+T+16], rdx
    mov     [rsp+T+24], r8
    ; E = 3*T
    mov     rax, [rsp+T]
    mov     rcx, [rsp+T+8]
    mov     rdx, [rsp+T+16]
    mov     r8, [rsp+T+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+E], rax
    mov     [rsp+E+8], rcx
    mov     [rsp+E+16], rdx
    mov     [rsp+E+24], r8
    ; E = E + T
    mov     rax, [rsp+E]
    mov     rcx, [rsp+E+8]
    mov     rdx, [rsp+E+16]
    mov     r8, [rsp+E+24]
    add     rax, [rsp+T]
    adc     rcx, [rsp+T+8]
    adc     rdx, [rsp+T+16]
    adc     r8, [rsp+T+24]
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+E], rax
    mov     [rsp+E+8], rcx
    mov     [rsp+E+16], rdx
    mov     [rsp+E+24], r8
    ; X3 = E^2
    lea     rcx, [rsp+X3]
    lea     rdx, [rsp+E]
    call    jpssl_p256_sqr_adx
    ; T = D + D; X3 = X3 - T
    mov     rax, [rsp+D]
    mov     rcx, [rsp+D+8]
    mov     rdx, [rsp+D+16]
    mov     r8, [rsp+D+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     r9, [rsp+X3]
    mov     r10, [rsp+X3+8]
    mov     r11, [rsp+X3+16]
    mov     rbx, [rsp+X3+24]
    sub     r9, rax
    sbb     r10, rcx
    sbb     r11, rdx
    sbb     rbx, r8
    setc    r13b
    movzx   r13d, r13b              ; r13 = borrow
    mov     r12, r9
    mov     rax, r10
    mov     rcx, r11
    mov     rdx, rbx
    add     r12, -1
    adc     rax, r14
    adc     rcx, 0
    adc     rdx, r15                ; r12,rax,rcx,rdx = a-b+p
    neg     r13                     ; CF = borrow
    cmovc   r9, r12
    cmovc   r10, rax
    cmovc   r11, rcx
    cmovc   rbx, rdx
    mov     [rsp+X3], r9
    mov     [rsp+X3+8], r10
    mov     [rsp+X3+16], r11
    mov     [rsp+X3+24], rbx
    ; T = D - X3
    mov     rax, [rsp+D]
    mov     rcx, [rsp+D+8]
    mov     rdx, [rsp+D+16]
    mov     r8, [rsp+D+24]
    sub     rax, r9
    sbb     rcx, r10
    sbb     rdx, r11
    sbb     r8, rbx
    setc    r12b
    movzx   r12d, r12b              ; r12 = borrow
    mov     r9, rax
    mov     r10, rcx
    mov     r11, rdx
    mov     r13, r8
    add     r9, -1
    adc     r10, r14
    adc     r11, 0
    adc     r13, r15                ; r9,r10,r11,r13 = a-b+p
    neg     r12                     ; CF = borrow
    cmovc   rax, r9
    cmovc   rcx, r10
    cmovc   rdx, r11
    cmovc   r8, r13
    mov     [rsp+T], rax
    mov     [rsp+T+8], rcx
    mov     [rsp+T+16], rdx
    mov     [rsp+T+24], r8
    ; Y3 = E * T
    lea     rcx, [rsp+Y3]
    lea     rdx, [rsp+E]
    lea     r8, [rsp+T]
    call    jpssl_p256_mul_adx
    ; T = 8*C
    mov     rax, [rsp+C]
    mov     rcx, [rsp+C+8]
    mov     rdx, [rsp+C+16]
    mov     r8, [rsp+C+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
mov     [rsp+T], rax
    mov     [rsp+T+8], rcx
    mov     [rsp+T+16], rdx
    mov     [rsp+T+24], r8
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     r9, [rsp+Y3]
    mov     r10, [rsp+Y3+8]
    mov     r11, [rsp+Y3+16]
    mov     rbx, [rsp+Y3+24]
    sub     r9, rax
    sbb     r10, rcx
    sbb     r11, rdx
    sbb     rbx, r8
    setc    r13b
    movzx   r13d, r13b              ; r13 = borrow
    mov     r12, r9
    mov     rax, r10
    mov     rcx, r11
    mov     rdx, rbx
    add     r12, -1
    adc     rax, r14
    adc     rcx, 0
    adc     rdx, r15                ; r12,rax,rcx,rdx = a-b+p
    neg     r13                     ; CF = borrow
    cmovc   r9, r12
    cmovc   r10, rax
    cmovc   r11, rcx
    cmovc   rbx, rdx
    mov     [rsp+Y3], r9
    mov     [rsp+Y3+8], r10
    mov     [rsp+Y3+16], r11
    mov     [rsp+Y3+24], rbx
    ; T = Y * Z
    lea     rcx, [rsp+T]
    lea     rdx, [rsp+Y]
    lea     r8, [rsp+Z]
    call    jpssl_p256_mul_adx
    ; Z3 = T + T
    mov     rax, [rsp+T]
    mov     rcx, [rsp+T+8]
    mov     rdx, [rsp+T+16]
    mov     r8, [rsp+T+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+Z3], rax
    mov     [rsp+Z3+8], rcx
    mov     [rsp+Z3+16], rdx
    mov     [rsp+Z3+24], r8

mov     rax, [rsp+X3]
    mov     rcx, [rsp+X3+8]
    mov     rdx, [rsp+X3+16]
    mov     r8, [rsp+X3+24]
    mov     [rdi], rax
    mov     [rdi+8], rcx
    mov     [rdi+16], rdx
    mov     [rdi+24], r8
    mov     rax, [rsp+Y3]
    mov     rcx, [rsp+Y3+8]
    mov     rdx, [rsp+Y3+16]
    mov     r8, [rsp+Y3+24]
    mov     [rdi+32], rax
    mov     [rdi+40], rcx
    mov     [rdi+48], rdx
    mov     [rdi+56], r8
    mov     rax, [rsp+Z3]
    mov     rcx, [rsp+Z3+8]
    mov     rdx, [rsp+Z3+16]
    mov     r8, [rsp+Z3+24]
    mov     [rdi+64], rax
    mov     [rdi+72], rcx
    mov     [rdi+80], rdx
    mov     [rdi+88], r8

    add     rsp, 384
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_dbl ENDP

; jpssl_p256_madd(rcx=r[12], rdx=p[12], r8=q[12]):
;   Jacobian 混合加 R = P + Q。Q 为仿射点（Z=one）或无穷远（Z=0）。
;   分支：P 无穷远（固定模式）与 H==0（可忽略概率）；Q 无穷远用无分支掩码。
;   域乘调用 jpssl_p256_mul_adx。

; 宏：dst = a + b mod p（栈偏移；r14=p 字 1, r15=p 字 3）
; 无分支归约：t = (a+b) - p mod 2^256，CF=borrow；
; 结果 = t + p*(borrow & ~carry_out)（a,b<p 时 carry_out==1 ⟹ borrow==1 且取 t）。
MODADD MACRO dst, a, b, sublab, nolab
    mov     rax, [rsp+a]
    mov     rcx, [rsp+a+8]
    mov     rdx, [rsp+a+16]
    mov     r8, [rsp+a+24]
    add     rax, [rsp+b]
    adc     rcx, [rsp+b+8]
    adc     rdx, [rsp+b+16]
    adc     r8, [rsp+b+24]
    setc    r9b
    movzx   r9d, r9b                ; r9 = carry_out
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15                 ; rax..r8 = t; CF = borrow
    setc    r10b
    movzx   r10d, r10b              ; r10 = borrow
    xor     r9d, 1                  ; r9 = ~carry_out
    and     r9d, r10d               ; r9 = mask（0/1）
    neg     r9                      ; mask 全 1 或 0
    mov     r10, r9
    and     r10, r14                ; p1 & mask
    mov     r11, r9
    and     r11, r15                ; p3 & mask
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+dst], rax
    mov     [rsp+dst+8], rcx
    mov     [rsp+dst+16], rdx
    mov     [rsp+dst+24], r8
ENDM

; 宏：dst = a - b mod p（无分支：借位则加 p，setc 保存借位 + neg 重建 CF 后 cmovc 选择）
MODSUB MACRO dst, a, b, sublab, nolab
    mov     rax, [rsp+a]
    mov     rcx, [rsp+a+8]
    mov     rdx, [rsp+a+16]
    mov     r8, [rsp+a+24]
    sub     rax, [rsp+b]
    sbb     rcx, [rsp+b+8]
    sbb     rdx, [rsp+b+16]
    sbb     r8, [rsp+b+24]          ; CF = borrow
    setc    r9b
    movzx   r9d, r9b
    mov     r10, rax
    mov     r11, rcx
    mov     r12, rdx
    mov     r13, r8
    add     r10, -1
    adc     r11, r14
    adc     r12, 0
    adc     r13, r15                ; r10..r13 = a-b+p
    neg     r9                      ; CF = (borrow != 0)
    cmovc   rax, r10
    cmovc   rcx, r11
    cmovc   rdx, r12
    cmovc   r8, r13
    mov     [rsp+dst], rax
    mov     [rsp+dst+8], rcx
    mov     [rsp+dst+16], rdx
    mov     [rsp+dst+24], r8
ENDM

jpssl_p256_madd PROC
M1X     EQU 0
M1Y     EQU 32
M1Z     EQU 64
MQX     EQU 96
MQY     EQU 128
MQZ     EQU 160
MZ1Z1   EQU 192
MU2     EQU 224
MS2     EQU 256
MH      EQU 288
MT      EQU 320
MR2     EQU 352
MI      EQU 384
MJ      EQU 416
MV      EQU 448
MX3     EQU 480
MY3     EQU 512
MZ3     EQU 544

    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, 576

    mov     rdi, rcx                    ; rdi = r
    mov     rsi, rdx                    ; rsi = p
    mov     rbx, r8                     ; rbx = q
    mov     r15, 0ffffffff00000001h     ; p word 3
    mov     r14, 0ffffffffh             ; p word 1

    ; 载入 P（rsi）与 Q（rbx）到栈帧
    mov     rax, [rsi]      ; X1
    mov     rcx, [rsi+8]
    mov     rdx, [rsi+16]
    mov     r8, [rsi+24]
    mov     [rsp+M1X], rax
    mov     [rsp+M1X+8], rcx
    mov     [rsp+M1X+16], rdx
    mov     [rsp+M1X+24], r8
    mov     rax, [rsi+32]   ; Y1
    mov     rcx, [rsi+40]
    mov     rdx, [rsi+48]
    mov     r8, [rsi+56]
    mov     [rsp+M1Y], rax
    mov     [rsp+M1Y+8], rcx
    mov     [rsp+M1Y+16], rdx
    mov     [rsp+M1Y+24], r8
    mov     rax, [rsi+64]   ; Z1
    mov     rcx, [rsi+72]
    mov     rdx, [rsi+80]
    mov     r8, [rsi+88]
    mov     [rsp+M1Z], rax
    mov     [rsp+M1Z+8], rcx
    mov     [rsp+M1Z+16], rdx
    mov     [rsp+M1Z+24], r8
    mov     rax, [rbx]      ; Xq
    mov     rcx, [rbx+8]
    mov     rdx, [rbx+16]
    mov     r8, [rbx+24]
    mov     [rsp+MQX], rax
    mov     [rsp+MQX+8], rcx
    mov     [rsp+MQX+16], rdx
    mov     [rsp+MQX+24], r8
    mov     rax, [rbx+32]   ; Yq
    mov     rcx, [rbx+40]
    mov     rdx, [rbx+48]
    mov     r8, [rbx+56]
    mov     [rsp+MQY], rax
    mov     [rsp+MQY+8], rcx
    mov     [rsp+MQY+16], rdx
    mov     [rsp+MQY+24], r8
    mov     rax, [rbx+64]   ; Zq
    mov     rcx, [rbx+72]
    mov     rdx, [rbx+80]
    mov     r8, [rbx+88]
    mov     [rsp+MQZ], rax
    mov     [rsp+MQZ+8], rcx
    mov     [rsp+MQZ+16], rdx
    mov     [rsp+MQZ+24], r8

    ; P 无穷远（Z1==0）→ R = Q
    mov     rax, [rsp+M1Z]
    or      rax, [rsp+M1Z+8]
    or      rax, [rsp+M1Z+16]
    or      rax, [rsp+M1Z+24]
    jnz     madd_p_notinf
    ; R = Q
    mov     rax, [rsp+MQX]
    mov     rcx, [rsp+MQX+8]
    mov     rdx, [rsp+MQX+16]
    mov     r8, [rsp+MQX+24]
    mov     [rdi], rax
    mov     [rdi+8], rcx
    mov     [rdi+16], rdx
    mov     [rdi+24], r8
    mov     rax, [rsp+MQY]
    mov     rcx, [rsp+MQY+8]
    mov     rdx, [rsp+MQY+16]
    mov     r8, [rsp+MQY+24]
    mov     [rdi+32], rax
    mov     [rdi+40], rcx
    mov     [rdi+48], rdx
    mov     [rdi+56], r8
    mov     rax, [rsp+MQZ]
    mov     rcx, [rsp+MQZ+8]
    mov     rdx, [rsp+MQZ+16]
    mov     r8, [rsp+MQZ+24]
    mov     [rdi+64], rax
    mov     [rdi+72], rcx
    mov     [rdi+80], rdx
    mov     [rdi+88], r8
    jmp     madd_done
madd_p_notinf:

    ; Z1Z1 = Z1^2
    lea     rcx, [rsp+MZ1Z1]
    lea     rdx, [rsp+M1Z]
    call    jpssl_p256_sqr_adx
    ; U2 = Xq * Z1Z1
    lea     rcx, [rsp+MU2]
    lea     rdx, [rsp+MQX]
    lea     r8, [rsp+MZ1Z1]
    call    jpssl_p256_mul_adx
    ; S2 = Yq * Z1 * Z1Z1
    lea     rcx, [rsp+MS2]
    lea     rdx, [rsp+MQY]
    lea     r8, [rsp+M1Z]
    call    jpssl_p256_mul_adx
    lea     rcx, [rsp+MS2]
    lea     rdx, [rsp+MS2]
    lea     r8, [rsp+MZ1Z1]
    call    jpssl_p256_mul_adx
    ; H = U2 - X1 ; T = S2 - Y1
    MODSUB  MH, MU2, M1X, madd_sub1, madd_no1
    MODSUB  MT, MS2, M1Y, madd_sub2, madd_no2

    ; H==0 例外（可忽略概率）：T==0 → dbl，否则无穷远
    mov     rax, [rsp+MH]
    or      rax, [rsp+MH+8]
    or      rax, [rsp+MH+16]
    or      rax, [rsp+MH+24]
    jnz     madd_h_nonzero
    mov     rax, [rsp+MT]
    or      rax, [rsp+MT+8]
    or      rax, [rsp+MT+16]
    or      rax, [rsp+MT+24]
    jnz     madd_h_inf
    ; R = dbl(P)
    mov     rcx, rdi
    mov     rdx, rsi
    call    jpssl_p256_dbl
    jmp     madd_done
madd_h_inf:
    lea     rbx, field_one
    mov     rax, [rbx]
    mov     rcx, [rbx+8]
    mov     rdx, [rbx+16]
    mov     r8, [rbx+24]
    mov     [rdi], rax
    mov     [rdi+8], rcx
    mov     [rdi+16], rdx
    mov     [rdi+24], r8
    mov     [rdi+32], rax
    mov     [rdi+40], rcx
    mov     [rdi+48], rdx
    mov     [rdi+56], r8
    mov     qword ptr [rdi+64], 0
    mov     qword ptr [rdi+72], 0
    mov     qword ptr [rdi+80], 0
    mov     qword ptr [rdi+88], 0
    jmp     madd_done

madd_h_nonzero:

    ; R2 = T + T（r=2(S2-S1)）
    mov     rax, [rsp+MT]
    mov     rcx, [rsp+MT+8]
    mov     rdx, [rsp+MT+16]
    mov     r8, [rsp+MT+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+MR2], rax
    mov     [rsp+MR2+8], rcx
    mov     [rsp+MR2+16], rdx
    mov     [rsp+MR2+24], r8
    ; I = (2H)^2
    mov     rax, [rsp+MH]
    mov     rcx, [rsp+MH+8]
    mov     rdx, [rsp+MH+16]
    mov     r8, [rsp+MH+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+MI], rax
    mov     [rsp+MI+8], rcx
    mov     [rsp+MI+16], rdx
    mov     [rsp+MI+24], r8
    lea     rcx, [rsp+MI]
    lea     rdx, [rsp+MI]
    call    jpssl_p256_sqr_adx
    ; J = H * I
    lea     rcx, [rsp+MJ]
    lea     rdx, [rsp+MH]
    lea     r8, [rsp+MI]
    call    jpssl_p256_mul_adx
    ; V = X1 * I
    lea     rcx, [rsp+MV]
    lea     rdx, [rsp+M1X]
    lea     r8, [rsp+MI]
    call    jpssl_p256_mul_adx
    ; X3 = R2^2 - J - 2V
    lea     rcx, [rsp+MX3]
    lea     rdx, [rsp+MR2]
    call    jpssl_p256_sqr_adx
    MODSUB  MX3, MX3, MJ, madd_sub5, madd_no5
    mov     rax, [rsp+MV]
    mov     rcx, [rsp+MV+8]
    mov     rdx, [rsp+MV+16]
    mov     r8, [rsp+MV+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     r9, [rsp+MX3]
    mov     r10, [rsp+MX3+8]
    mov     r11, [rsp+MX3+16]
    mov     rbx, [rsp+MX3+24]
    sub     r9, rax
    sbb     r10, rcx
    sbb     r11, rdx
    sbb     rbx, r8
    setc    r12b
    movzx   r12d, r12b              ; r12 = borrow
    mov     r13, r9
    mov     rax, r10
    mov     rcx, r11
    mov     rdx, rbx
    add     r13, -1
    adc     rax, r14
    adc     rcx, 0
    adc     rdx, r15                ; r13,rax,rcx,rdx = a-b+p
    neg     r12                     ; CF = borrow
    cmovc   r9, r13
    cmovc   r10, rax
    cmovc   r11, rcx
    cmovc   rbx, rdx
    mov     [rsp+MX3], r9
    mov     [rsp+MX3+8], r10
    mov     [rsp+MX3+16], r11
    mov     [rsp+MX3+24], rbx
    ; Y3 = R2 * (V - X3) - 2*Y1*J
    MODSUB  MT, MV, MX3, madd_sub8, madd_no8
    lea     rcx, [rsp+MY3]
    lea     rdx, [rsp+MR2]
    lea     r8, [rsp+MT]
    call    jpssl_p256_mul_adx
    lea     rcx, [rsp+MT]
    lea     rdx, [rsp+M1Y]
    lea     r8, [rsp+MJ]
    call    jpssl_p256_mul_adx
    mov     rax, [rsp+MT]
    mov     rcx, [rsp+MT+8]
    mov     rdx, [rsp+MT+16]
    mov     r8, [rsp+MT+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     r9, [rsp+MY3]
    mov     r10, [rsp+MY3+8]
    mov     r11, [rsp+MY3+16]
    mov     rbx, [rsp+MY3+24]
    sub     r9, rax
    sbb     r10, rcx
    sbb     r11, rdx
    sbb     rbx, r8
    setc    r12b
    movzx   r12d, r12b              ; r12 = borrow
    mov     r13, r9
    mov     rax, r10
    mov     rcx, r11
    mov     rdx, rbx
    add     r13, -1
    adc     rax, r14
    adc     rcx, 0
    adc     rdx, r15                ; r13,rax,rcx,rdx = a-b+p
    neg     r12                     ; CF = borrow
    cmovc   r9, r13
    cmovc   r10, rax
    cmovc   r11, rcx
    cmovc   rbx, rdx
    mov     [rsp+MY3], r9
    mov     [rsp+MY3+8], r10
    mov     [rsp+MY3+16], r11
    mov     [rsp+MY3+24], rbx
    ; Z3 = 2 * Z1 * H
    lea     rcx, [rsp+MZ3]
    lea     rdx, [rsp+M1Z]
    lea     r8, [rsp+MH]
    call    jpssl_p256_mul_adx
    mov     rax, [rsp+MZ3]
    mov     rcx, [rsp+MZ3+8]
    mov     rdx, [rsp+MZ3+16]
    mov     r8, [rsp+MZ3+24]
    add     rax, rax
    adc     rcx, rcx
    adc     rdx, rdx
    adc     r8, r8
    setc    r9b
    movzx   r9d, r9b
    sub     rax, -1
    sbb     rcx, r14
    sbb     rdx, 0
    sbb     r8, r15
    setc    r10b
    movzx   r10d, r10b
    xor     r9d, 1
    and     r9d, r10d
    neg     r9
    mov     r10, r9
    and     r10, r14
    mov     r11, r9
    and     r11, r15
    add     rax, r9
    adc     rcx, r10
    adc     rdx, 0
    adc     r8, r11
    mov     [rsp+MZ3], rax
    mov     [rsp+MZ3+8], rcx
    mov     [rsp+MZ3+16], rdx
    mov     [rsp+MZ3+24], r8

    ; Q 无穷远（Zq==0）→ 无分支掩码：R = P
    mov     rax, [rsp+MQZ]
    or      rax, [rsp+MQZ+8]
    or      rax, [rsp+MQZ+16]
    or      rax, [rsp+MQZ+24]
    neg     rax                         ; CF = (Zq != 0)
    sbb     r9, r9                      ; r9 = -(Zq != 0)
    mov     r10, r9
    not     r10                         ; r10 = mask_q (all-ones if Zq==0)
    ; R.X = (X3 & keep) | (P.X & mask_q)
    mov     rax, [rsp+MX3]
    and     rax, r9
    mov     rcx, [rsp+M1X]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi], rax
    mov     rax, [rsp+MX3+8]
    and     rax, r9
    mov     rcx, [rsp+M1X+8]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+8], rax
    mov     rax, [rsp+MX3+16]
    and     rax, r9
    mov     rcx, [rsp+M1X+16]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+16], rax
    mov     rax, [rsp+MX3+24]
    and     rax, r9
    mov     rcx, [rsp+M1X+24]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+24], rax
    ; R.Y
    mov     rax, [rsp+MY3]
    and     rax, r9
    mov     rcx, [rsp+M1Y]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+32], rax
    mov     rax, [rsp+MY3+8]
    and     rax, r9
    mov     rcx, [rsp+M1Y+8]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+40], rax
    mov     rax, [rsp+MY3+16]
    and     rax, r9
    mov     rcx, [rsp+M1Y+16]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+48], rax
    mov     rax, [rsp+MY3+24]
    and     rax, r9
    mov     rcx, [rsp+M1Y+24]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+56], rax
    ; R.Z
    mov     rax, [rsp+MZ3]
    and     rax, r9
    mov     rcx, [rsp+M1Z]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+64], rax
    mov     rax, [rsp+MZ3+8]
    and     rax, r9
    mov     rcx, [rsp+M1Z+8]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+72], rax
    mov     rax, [rsp+MZ3+16]
    and     rax, r9
    mov     rcx, [rsp+M1Z+16]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+80], rax
    mov     rax, [rsp+MZ3+24]
    and     rax, r9
    mov     rcx, [rsp+M1Z+24]
    and     rcx, r10
    or      rax, rcx
    mov     [rdi+88], rax

madd_done:
    add     rsp, 576
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_madd ENDP

; ============================================================================
; jpssl_p256_inv_adx(rcx=r[4], rdx=a[4]): r = a^{-1} mod p (Montgomery domain)
;
; Exponentiation with exponent p-2, using the addchain v0.4.0 sequence from
; crypto/internal/nistec/fiat/p256_invert.go (12 mul + 255 sq):
;   _10=x^2 _11=x^3 _110=x^6 _111=x^7 _111000=x^56 _111111=x^63
;   x12=x^4095 x15=x^32767 x16=x^65535 x32=x^(2^32-1) i53=x^(2^47-2^15)
;   x47=x^(2^47-1) i263=(x47+i263) ... return (x47+i263)^4*x = x^(p-2)
; Every step calls jpssl_p256_mul_adx, whose output is fully reduced (< p).
; Input a may alias output r (a is copied to the stack first).
; ============================================================================
jpssl_p256_inv_adx PROC
X      EQU 0
T0     EQU 32
T1     EQU 64
T2     EQU 96
T3     EQU 128
T4     EQU 160
T5     EQU 192
T6     EQU 224
T7     EQU 256
T8     EQU 288
T9     EQU 320
T10    EQU 352
T11    EQU 384
T12    EQU 416
FRSZ   EQU 448

MODMUL MACRO dst:REQ, s1:REQ, s2:REQ
    lea     rcx, dst
    lea     rdx, s1
    IFIDN   <s1>, <s2>
        call    jpssl_p256_sqr_adx
    ELSE
        lea     r8, s2
        call    jpssl_p256_mul_adx
    ENDIF
ENDM

    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, FRSZ

    mov     rdi, rcx                ; rdi = output pointer
    ; copy a -> [rsp+X] (input may alias output)
    mov     rax, [rdx]
    mov     rcx, [rdx+8]
    mov     r9, [rdx+16]
    mov     r10, [rdx+24]
    mov     [rsp+X], rax
    mov     [rsp+X+8], rcx
    mov     [rsp+X+16], r9
    mov     [rsp+X+24], r10

    ; T0 = x^2
    MODMUL [rsp+T0], [rsp+X], [rsp+X]
    ; T1 = x^3
    MODMUL [rsp+T1], [rsp+T0], [rsp+X]
    ; T2 = x^6
    MODMUL [rsp+T2], [rsp+T1], [rsp+T1]
    ; T3 = x^7
    MODMUL [rsp+T3], [rsp+T2], [rsp+X]
    ; T4 = x^56
    MODMUL [rsp+T4], [rsp+T3], [rsp+T3]
    MODMUL [rsp+T4], [rsp+T4], [rsp+T4]
    MODMUL [rsp+T4], [rsp+T4], [rsp+T4]
    ; T5 = x^63
    MODMUL [rsp+T5], [rsp+T3], [rsp+T4]
    ; T6 = x^4095
    MODMUL [rsp+T6], [rsp+T5], [rsp+T5]
    MODMUL [rsp+T6], [rsp+T6], [rsp+T6]
    MODMUL [rsp+T6], [rsp+T6], [rsp+T6]
    MODMUL [rsp+T6], [rsp+T6], [rsp+T6]
    MODMUL [rsp+T6], [rsp+T6], [rsp+T6]
    MODMUL [rsp+T6], [rsp+T6], [rsp+T6]
    MODMUL [rsp+T6], [rsp+T6], [rsp+T5]
    ; T7 = x^32767
    MODMUL [rsp+T7], [rsp+T6], [rsp+T6]
    MODMUL [rsp+T7], [rsp+T7], [rsp+T7]
    MODMUL [rsp+T7], [rsp+T7], [rsp+T7]
    MODMUL [rsp+T7], [rsp+T7], [rsp+T3]
    ; T8 = x^65535
    MODMUL [rsp+T8], [rsp+T7], [rsp+T7]
    MODMUL [rsp+T8], [rsp+T8], [rsp+X]

    ; T9 = x^(2^32-1) : 16 squarings then mul by T8
    MODMUL [rsp+T9], [rsp+T8], [rsp+T8]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T9], [rsp+T9], [rsp+T8]

    ; T10 = x^(2^47-2^15) : 15 squarings from T9
    MODMUL [rsp+T10], [rsp+T9], [rsp+T9]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T10], [rsp+T10], [rsp+T10]

    ; T11 = x^(2^47-1)
    MODMUL [rsp+T11], [rsp+T7], [rsp+T10]

    ; T12 = x^(2^64-2^32+1) : 17 squarings of T10 then mul by X
    MODMUL [rsp+T12], [rsp+T10], [rsp+T10]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+X]

    ; T12 = T12^(2^143) : 143 squarings
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T11]

    ; T12 = T12^(2^47) : 47 squarings
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]

    ; result = T11*T12, then ^4, then * x
    MODMUL [rsp+T12], [rsp+T11], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+T12]
    MODMUL [rsp+T12], [rsp+T12], [rsp+X]

    ; store result to [rdi]
    mov     rax, [rsp+T12]
    mov     rcx, [rsp+T12+8]
    mov     rdx, [rsp+T12+16]
    mov     r8, [rsp+T12+24]
    mov     [rdi], rax
    mov     [rdi+8], rcx
    mov     [rdi+16], rdx
    mov     [rdi+24], r8

    add     rsp, FRSZ
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_inv_adx ENDP

; jpssl_p256_sqr_adx(rcx=r, rdx=a): r = a*a*R^{-1} mod p, R = 2^256.
; Ported from OpenSSL __ecp_nistz256_sqr_montx (ecp_nistz256-x86_64.pl):
; Gueron-Krasnov squaring (doubled cross products + squares) followed by the
; 4-step special-form Montgomery reduction. Requires BMI2 + ADX.
;
; Register map (same as the perlasm source):
;   acc0..acc7 = r8..r15, t0 = rcx, t1 = rbp, t2 = rbx, t3 = rdx, t4 = rax
;   r_ptr = rdi, a_ptr = rsi
.code
align 16
jpssl_p256_sqr_adx PROC
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    mov     rdi, rcx                     ; r_ptr
    mov     rsi, rdx                     ; a_ptr

    mov     rdx, qword ptr [rsi]         ; rdx = a[0]
    mov     r14, qword ptr [rsi+8]       ; acc6 = a[1]
    mov     r15, qword ptr [rsi+16]      ; acc7 = a[2]
    mov     r8,  qword ptr [rsi+24]      ; acc0 = a[3]

    ; ---- cross products ----
    mulx    r10, r9,  r14                ; a0*a1: hi=acc2, lo=acc1
    mulx    r11, rcx, r15                ; a0*a2: hi=acc3, lo=t0
    xor     eax, eax
    adc     r10, rcx                     ; acc2 += t0
    mulx    r12, rbp, r8                 ; a0*a3: hi=acc4, lo=t1
    mov     rdx, r14                     ; rdx = a1
    adc     r11, rbp                     ; acc3 += t1
    adc     r12, 0                       ; acc4 += carry
    xor     r13, r13                     ; acc5 = 0 (cf=of=0)

    mulx    rbp, rcx, r15                ; a1*a2: hi=t1, lo=t0
    adcx    r11, rcx                     ; acc3 += t0
    adox    r12, rbp                     ; acc4 += t1

    mulx    rbp, rcx, r8                 ; a1*a3: hi=t1, lo=t0
    mov     rdx, r15                     ; rdx = a2
    adcx    r12, rcx                     ; acc4 += t0
    adox    r13, rbp                     ; acc5 += t1
    adc     r13, 0                       ; acc5 += carry

    mulx    r14, rcx, r8                 ; a2*a3: hi=acc6, lo=t0
    mov     rdx, qword ptr [rsi]         ; rdx = a0
    xor     r15, r15                     ; acc7 = 0 (cf=of=0)
    adcx    r9,  r9                      ; acc1 <<= 1
    adox    r13, rcx                     ; acc5 += t0
    adcx    r10, r10                     ; acc2 <<= 1
    adox    r14, r15                     ; acc6 += 0 (of=0)

    ; ---- squares ----
    mulx    rbp, r8,  qword ptr [rsi]    ; a0*a0: hi=t1, lo=acc0
    mov     rdx, qword ptr [rsi+8]       ; rdx = a1
    adcx    r11, r11                     ; acc3 <<= 1
    adox    r9,  rbp                     ; acc1 += a0^2.hi
    adcx    r12, r12                     ; acc4 <<= 1
    mulx    rax, rcx, qword ptr [rsi+8]  ; a1*a1: hi=t4, lo=t0
    mov     rdx, qword ptr [rsi+16]      ; rdx = a2
    adcx    r13, r13                     ; acc5 <<= 1
    adox    r10, rcx                     ; acc2 += a1^2.lo
    adcx    r14, r14                     ; acc6 <<= 1
    mulx    rbp, rcx, qword ptr [rsi+16] ; a2*a2: hi=t1, lo=t0
    mov     rdx, qword ptr [rsi+24]      ; rdx = a3
    adox    r11, rax                     ; acc3 += a1^2.hi
    adcx    r15, r15                     ; acc7 <<= 1
    adox    r12, rcx                     ; acc4 += a2^2.lo
    mov     rbx, rdx                     ; t2 = a3 (for the square below)
    mov     rsi, 32                      ; shift count
    adox    r13, rbp                     ; acc5 += a2^2.hi
    mulx    rax, rcx, rbx                ; a3*a3: hi=t4, lo=t0
    mov     rdx, 0ffffffff00000001h      ; rdx = poly3
    adox    r14, rcx                     ; acc6 += a3^2.lo
    shlx    rcx, r8, rsi                 ; t0 = acc0 << 32
    adox    r15, rax                     ; acc7 += a3^2.hi
    shrx    rax, r8, rsi                 ; t4 = acc0 >> 32
    mov     rbp, rdx                     ; t1 = poly3

    ; ---- Montgomery reduction (4 steps) ----
    add     r9,  rcx                     ; acc1 += acc0<<32
    adc     r10, rax                     ; acc2 += acc0>>32
    mulx    r8,  rcx, r8                 ; poly3*acc0: hi=acc0, lo=t0
    adc     r11, rcx                     ; acc3 += t0
    shlx    rcx, r9, rsi                 ; t0 = acc1 << 32
    adc     r8,  0                       ; acc0 += carry
    shrx    rax, r9, rsi                 ; t4 = acc1 >> 32

    add     r10, rcx                     ; acc2 += acc1<<32
    adc     r11, rax                     ; acc3 += acc1>>32
    mulx    r9,  rcx, r9                 ; poly3*acc1: hi=acc1, lo=t0
    adc     r8,  rcx                     ; acc0 += t0
    shlx    rcx, r10, rsi                ; t0 = acc2 << 32
    adc     r9,  0                       ; acc1 += carry
    shrx    rax, r10, rsi                ; t4 = acc2 >> 32

    add     r11, rcx                     ; acc3 += acc2<<32
    adc     r8,  rax                     ; acc0 += acc2>>32
    mulx    r10, rcx, r10                ; poly3*acc2: hi=acc2, lo=t0
    adc     r9,  rcx                     ; acc1 += t0
    shlx    rcx, r11, rsi                ; t0 = acc3 << 32
    adc     r10, 0                       ; acc2 += carry
    shrx    rax, r11, rsi                ; t4 = acc3 >> 32

    add     r8,  rcx                     ; acc0 += acc3<<32
    adc     r9,  rax                     ; acc1 += acc3>>32
    mulx    r11, rcx, r11                ; poly3*acc3: hi=acc3, lo=t0
    adc     r10, rcx                     ; acc2 += t0
    adc     r11, 0                       ; acc3 += carry

    ; ---- fold upper half + branch-less conditional subtraction of p ----
    xor     rdx, rdx                     ; t3 = 0
    add     r12, r8                      ; acc4 += acc0
    mov     rsi, 00000000ffffffffh       ; a_ptr = poly1
    adc     r13, r9                      ; acc5 += acc1
    mov     r8,  r12                     ; acc0 = acc4
    adc     r14, r10                     ; acc6 += acc2
    adc     r15, r11                     ; acc7 += acc3
    mov     r9,  r13                     ; acc1 = acc5
    adc     rdx, 0                       ; t3 += carry

    sub     r12, -1                      ; acc4 -= poly[0]
    mov     r10, r14                     ; acc2 = acc6
    sbb     r13, rsi                     ; acc5 -= poly1
    sbb     r14, 0                       ; acc6 -= 0
    mov     r11, r15                     ; acc3 = acc7
    sbb     r15, rbp                     ; acc7 -= poly3
    sbb     rdx, 0                       ; t3 -= 0

    cmovc   r12, r8                      ; restore acc4 if borrow
    cmovc   r13, r9                      ; restore acc5
    mov     qword ptr [rdi], r12
    cmovc   r14, r10                     ; restore acc6
    mov     qword ptr [rdi+8], r13
    cmovc   r15, r11                     ; restore acc7
    mov     qword ptr [rdi+16], r14
    mov     qword ptr [rdi+24], r15

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_sqr_adx ENDP

; ============================================================================
; jpssl_p256_ord_inv_adx(rcx=r, rdx=a): r = a^{-1} mod n (P-256 order field).
; Addition chain for n-2 generated by gen_ord_inv_chain.py (sliding window 4):
;   318 ops (253 sqr + 65 mul), all via jpssl_p256_ord_mul_adx.
; Input a may alias output r (a is copied to the stack first).
; ============================================================================
jpssl_p256_ord_inv_adx PROC
EXTERN ecp_nistz256_ord_sqr_mont:PROC
OX     EQU 32      ; leave rsp+0..31 as shadow space for callees
OT0   EQU 64
OT1   EQU 96
OT2   EQU 128
OT3   EQU 160
OT4   EQU 192
OT5   EQU 224
OT6   EQU 256
OT7   EQU 288
OT8   EQU 320
OT9   EQU 352
OT10   EQU 384
OT11   EQU 416
OT12   EQU 448
OFRSZ  EQU 480

ORDMODMUL MACRO dst:REQ, s1:REQ, s2:REQ
    lea     rcx, dst
    lea     rdx, s1
    IFIDN   <s1>, <s2>
        mov     r8d, 1
        call    ecp_nistz256_ord_sqr_mont
    ELSE
        lea     r8, s2
        call    jpssl_p256_ord_mul_adx
    ENDIF
ENDM

    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, OFRSZ

    mov     rdi, rcx                ; output pointer
    mov     rax, [rdx]
    mov     rcx, [rdx+8]
    mov     r9, [rdx+16]
    mov     r10, [rdx+24]
    mov     [rsp+OX], rax
    mov     [rsp+OX+8], rcx
    mov     [rsp+OX+16], r9
    mov     [rsp+OX+24], r10

    ; ---- addition chain for a^(n-2) - 318 ops -------
ORDMODMUL [rsp+OT0], [rsp+OX], [rsp+OX]
    ORDMODMUL [rsp+OT1], [rsp+OX], [rsp+OT0]
    ORDMODMUL [rsp+OT2], [rsp+OT1], [rsp+OT0]
    ORDMODMUL [rsp+OT3], [rsp+OT2], [rsp+OT0]
    ORDMODMUL [rsp+OT4], [rsp+OT3], [rsp+OT0]
    ORDMODMUL [rsp+OT5], [rsp+OT4], [rsp+OT0]
    ORDMODMUL [rsp+OT6], [rsp+OT5], [rsp+OT0]
    ORDMODMUL [rsp+OT7], [rsp+OT6], [rsp+OT0]
    ORDMODMUL [rsp+OT12], [rsp+OT7], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT3]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT1]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT1]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT1]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT3]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT3]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT3]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT3]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT1]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT1]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT1]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT1]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OX]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT12]
    ORDMODMUL [rsp+OT12], [rsp+OT12], [rsp+OT7]

    ; store result to [rdi]
    mov     rax, [rsp+OT12]
    mov     rcx, [rsp+OT12+8]
    mov     rdx, [rsp+OT12+16]
    mov     r8, [rsp+OT12+24]
    mov     [rdi], rax
    mov     [rdi+8], rcx
    mov     [rdi+16], rdx
    mov     [rdi+24], r8

    add     rsp, OFRSZ
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_ord_inv_adx ENDP




; ============================================================================
; jpssl_p256_comb_mul_G(rcx=r, rdx=k, r8=table, r9=one):
;   r = k*G via a 64-window 4-bit comb (constant time).
;   table: 64 windows x 15 affine points (each 64 bytes: X[4] Y[4], Montgomery)
;     table[i][d-1] = d * 2^(4i) * G, d in [1,15]; window stride 960 bytes.
;   k: bn<4> (32 bytes); r: jac_point<4> (96 bytes) = k*G (Jacobian).
;   one: Montgomery 1 (4 limbs), used for Z of affine entries / infinity.
; ============================================================================
.code
align 16
jpssl_p256_comb_mul_G PROC
R      EQU 0
Q      EQU 96
K      EQU 192
DIG    EQU 224
FRSZ2  EQU 232

    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi
    sub     rsp, FRSZ2

    mov     rdi, rcx                ; r_ptr
    mov     rsi, rdx                ; k_ptr
    mov     rbx, r8                 ; table
    mov     rbp, r9                 ; one

    ; copy k to the stack frame
    mov     rax, [rsi]
    mov     [rsp+K], rax
    mov     rax, [rsi+8]
    mov     [rsp+K+8], rax
    mov     rax, [rsi+16]
    mov     [rsp+K+16], rax
    mov     rax, [rsi+24]
    mov     [rsp+K+24], rax

    ; R = infinity (X=one, Y=one, Z=0)
    mov     rax, [rbp]
    mov     [rsp+R], rax
    mov     rax, [rbp+8]
    mov     [rsp+R+8], rax
    mov     rax, [rbp+16]
    mov     [rsp+R+16], rax
    mov     rax, [rbp+24]
    mov     [rsp+R+24], rax
    mov     rax, [rbp]
    mov     [rsp+R+32], rax
    mov     rax, [rbp+8]
    mov     [rsp+R+40], rax
    mov     rax, [rbp+16]
    mov     [rsp+R+48], rax
    mov     rax, [rbp+24]
    mov     [rsp+R+56], rax
    xor     eax, eax
    mov     [rsp+R+64], rax
    mov     [rsp+R+72], rax
    mov     [rsp+R+80], rax
    mov     [rsp+R+88], rax

    xor     r12, r12                ; window index
    mov     r15, rbx                ; window base pointer
comb_loop:
    ; digit = k & 15
    mov     rax, [rsp+K]
    and     rax, 15
    mov     [rsp+DIG], rax

    ; constant-time 15-way select into Q (X, Y, Z)
    xor     r13, r13                ; any = 0
    pxor    xmm0, xmm0
    movdqu  [rsp+Q], xmm0
    movdqu  [rsp+Q+16], xmm0
    movdqu  [rsp+Q+32], xmm0
    movdqu  [rsp+Q+48], xmm0
    movdqu  [rsp+Q+64], xmm0
    movdqu  [rsp+Q+80], xmm0
    xor     r14, r14                ; entry byte offset
comb_sel:
    mov     rax, [rsp+DIG]
    mov     rcx, r14
    shr     rcx, 6
    inc     rcx
    xor     rdx, rdx
    cmp     rax, rcx
    sete    dl
    neg     rdx
    or      r13, rdx
    mov     rax, [r15+r14]
    and     rax, rdx
    or      [rsp+Q], rax
    mov     rax, [r15+r14+8]
    and     rax, rdx
    or      [rsp+Q+8], rax
    mov     rax, [r15+r14+16]
    and     rax, rdx
    or      [rsp+Q+16], rax
    mov     rax, [r15+r14+24]
    and     rax, rdx
    or      [rsp+Q+24], rax
    mov     rax, [r15+r14+32]
    and     rax, rdx
    or      [rsp+Q+32], rax
    mov     rax, [r15+r14+40]
    and     rax, rdx
    or      [rsp+Q+40], rax
    mov     rax, [r15+r14+48]
    and     rax, rdx
    or      [rsp+Q+48], rax
    mov     rax, [r15+r14+56]
    and     rax, rdx
    or      [rsp+Q+56], rax
    add     r14, 64
    cmp     r14, 960
    jb      comb_sel

    ; Z = one & any
    mov     rax, [rbp]
    and     rax, r13
    mov     [rsp+Q+64], rax
    mov     rax, [rbp+8]
    and     rax, r13
    mov     [rsp+Q+72], rax
    mov     rax, [rbp+16]
    and     rax, r13
    mov     [rsp+Q+80], rax
    mov     rax, [rbp+24]
    and     rax, r13
    mov     [rsp+Q+88], rax

    ; R = R + Q
    lea     rcx, [rsp+R]
    lea     rdx, [rsp+R]
    lea     r8, [rsp+Q]
    call    jpssl_p256_madd

    ; k >>= 4
    mov     rax, [rsp+K]
    mov     rcx, [rsp+K+8]
    mov     rdx, [rsp+K+16]
    mov     r8, [rsp+K+24]
    shrd    rax, rcx, 4
    shrd    rcx, rdx, 4
    shrd    rdx, r8, 4
    shr     r8, 4
    mov     [rsp+K], rax
    mov     [rsp+K+8], rcx
    mov     [rsp+K+16], rdx
    mov     [rsp+K+24], r8

    add     r15, 960
    inc     r12
    cmp     r12, 64
    jb      comb_loop

    ; store R
    mov     rax, [rsp+R]
    mov     [rdi], rax
    mov     rax, [rsp+R+8]
    mov     [rdi+8], rax
    mov     rax, [rsp+R+16]
    mov     [rdi+16], rax
    mov     rax, [rsp+R+24]
    mov     [rdi+24], rax
    mov     rax, [rsp+R+32]
    mov     [rdi+32], rax
    mov     rax, [rsp+R+40]
    mov     [rdi+40], rax
    mov     rax, [rsp+R+48]
    mov     [rdi+48], rax
    mov     rax, [rsp+R+56]
    mov     [rdi+56], rax
    mov     rax, [rsp+R+64]
    mov     [rdi+64], rax
    mov     rax, [rsp+R+72]
    mov     [rdi+72], rax
    mov     rax, [rsp+R+80]
    mov     [rdi+80], rax
    mov     rax, [rsp+R+88]
    mov     [rdi+88], rax

    add     rsp, FRSZ2
    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_comb_mul_G ENDP

; ============================================================================
; jpssl_p256_gather_w7(rcx=val[8], rdx=table, r8d=index):
;   Constant-time gather of one 64-byte affine entry from a w7 precomputed
;   frame. Semantics (same as OpenSSL ecp_nistz256_gather_w7):
;     index == 0 -> all-zero point (infinity)
;     index  k   -> frame entry k-1 (k-th multiple, 1..64)
;   Table entries are 64 bytes (X[4] Y[4]); frames are 64 entries.
; ============================================================================
.code
align 16
jpssl_p256_gather_w7 PROC
    sub     rsp, 168
    movaps  [rsp], xmm6
    movaps  [rsp+16], xmm7
    movaps  [rsp+32], xmm8
    movaps  [rsp+48], xmm9
    movaps  [rsp+64], xmm10
    movaps  [rsp+80], xmm11
    movaps  [rsp+96], xmm12
    movaps  [rsp+112], xmm13
    movaps  [rsp+128], xmm14
    movaps  [rsp+144], xmm15

    mov     eax, 1
    movd    xmm0, eax
    pshufd  xmm0, xmm0, 0            ; xmm0 = counter (dword 1s)
    movd    xmm1, r8d
    pshufd  xmm1, xmm1, 0            ; xmm1 = index broadcast
    pxor    xmm2, xmm2               ; acc limbs 0-3
    pxor    xmm3, xmm3               ; acc limbs 4-7
    pxor    xmm4, xmm4               ; acc limbs 8-11
    pxor    xmm5, xmm5               ; acc limbs 12-15
    movdqa  xmm7, xmm0               ; ones (for increment)
    mov     eax, 64
select_loop_w7:
    movdqa  xmm6, xmm0
    paddd   xmm0, xmm7
    pcmpeqd xmm6, xmm1               ; mask = (counter == index)
    movdqa  xmm8, [rdx]
    movdqa  xmm9, [rdx+16]
    movdqa  xmm10, [rdx+32]
    movdqa  xmm11, [rdx+48]
    add     rdx, 64
    pand    xmm8, xmm6
    pand    xmm9, xmm6
    por     xmm2, xmm8
    pand    xmm10, xmm6
    por     xmm3, xmm9
    pand    xmm11, xmm6
    por     xmm4, xmm10
    por     xmm5, xmm11
    dec     eax
    jnz     select_loop_w7

    movdqu  [rcx], xmm2
    movdqu  [rcx+16], xmm3
    movdqu  [rcx+32], xmm4
    movdqu  [rcx+48], xmm5

    movaps  xmm6, [rsp]
    movaps  xmm7, [rsp+16]
    movaps  xmm8, [rsp+32]
    movaps  xmm9, [rsp+48]
    movaps  xmm10, [rsp+64]
    movaps  xmm11, [rsp+80]
    movaps  xmm12, [rsp+96]
    movaps  xmm13, [rsp+112]
    movaps  xmm14, [rsp+128]
    movaps  xmm15, [rsp+144]
    add     rsp, 168
    ret
jpssl_p256_gather_w7 ENDP

; ============================================================================
; jpssl_p256_gather_w7_avx2(rcx=val[8], rdx=table, r8d=index):
;   Constant-time AVX2 gather, same semantics as the SSE version but with
;   256-bit compare/mask (8 dwords per op) - faster on AVX2 CPUs.
; ============================================================================
.code
align 16
jpssl_p256_gather_w7_avx2 PROC
    sub     rsp, 328
    vmovdqu ymmword ptr [rsp], ymm6
    vmovdqu ymmword ptr [rsp+32], ymm7
    vmovdqu ymmword ptr [rsp+64], ymm8
    vmovdqu ymmword ptr [rsp+96], ymm9
    vmovdqu ymmword ptr [rsp+128], ymm10
    vmovdqu ymmword ptr [rsp+160], ymm11
    vmovdqu ymmword ptr [rsp+192], ymm12
    vmovdqu ymmword ptr [rsp+224], ymm13
    vmovdqu ymmword ptr [rsp+256], ymm14
    vmovdqu ymmword ptr [rsp+288], ymm15

    vmovd   xmm1, r8d
    vpbroadcastd ymm1, xmm1        ; index (8 dwords)
    vpcmpeqd ymm3, ymm3, ymm3      ; -1s
    vpsrld  ymm2, ymm3, 31         ; counter = 1s
    vpsrld  ymm7, ymm3, 31         ; ones (increment)
    vpxor   ymm4, ymm4, ymm4       ; acc X
    vpxor   ymm5, ymm5, ymm5       ; acc Y
    mov     eax, 64
select_loop_avx2:
    vpcmpeqd ymm6, ymm2, ymm1      ; mask = (counter == index)
    vmovdqu ymm8, ymmword ptr [rdx]
    vmovdqu ymm9, ymmword ptr [rdx+32]
    add     rdx, 64
    vpand   ymm8, ymm8, ymm6
    vpand   ymm9, ymm9, ymm6
    vpor    ymm4, ymm4, ymm8
    vpor    ymm5, ymm5, ymm9
    vpaddd  ymm2, ymm2, ymm7
    dec     eax
    jnz     select_loop_avx2

    vmovdqu ymmword ptr [rcx], ymm4
    vmovdqu ymmword ptr [rcx+32], ymm5

    vmovdqu ymm6, ymmword ptr [rsp]
    vmovdqu ymm7, ymmword ptr [rsp+32]
    vmovdqu ymm8, ymmword ptr [rsp+64]
    vmovdqu ymm9, ymmword ptr [rsp+96]
    vmovdqu ymm10, ymmword ptr [rsp+128]
    vmovdqu ymm11, ymmword ptr [rsp+160]
    vmovdqu ymm12, ymmword ptr [rsp+192]
    vmovdqu ymm13, ymmword ptr [rsp+224]
    vmovdqu ymm14, ymmword ptr [rsp+256]
    vmovdqu ymm15, ymmword ptr [rsp+288]
    add     rsp, 328
        vzeroupper
ret
jpssl_p256_gather_w7_avx2 ENDP

; ============================================================================
; jpssl_p256_neg(rcx=r[4], rdx=a[4]): r = -a mod p (branchless)
; ============================================================================
.code
align 16
jpssl_p256_neg PROC
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    push    rsi
    push    rdi

    mov     rdi, rcx                 ; r_ptr
    mov     rsi, rdx                 ; a_ptr
    mov     r14, 0ffffffffh          ; p1 = 0x00000000ffffffff
    mov     r15, 0ffffffff00000001h  ; p3

    xor     r8, r8
    xor     r9, r9
    xor     r10, r10
    xor     r11, r11
    xor     rax, rax
    sub     r8, qword ptr [rsi]      ; 0 - a0
    sbb     r9, qword ptr [rsi+8]
    sbb     r10, qword ptr [rsi+16]
    mov     r12, r8                  ; save t0
    sbb     r11, qword ptr [rsi+24]
    mov     r13, r9                  ; save t1
    sbb     rax, 0                   ; rax = -borrow (0 or -1)
    mov     rbx, r10                 ; save t2
    mov     rbp, r11                 ; save t3
    add     r8, -1                   ; + p0 (0xffffffffffffffff)
    adc     r9, r14                  ; + p1 (0x00000000ffffffff)
    adc     r10, 0
    adc     r11, r15                 ; + p3
    test    rax, rax
    cmovz   r8, r12
    cmovz   r9, r13
    mov     qword ptr [rdi], r8
    cmovz   r10, rbx
    mov     qword ptr [rdi+8], r9
    cmovz   r11, rbp
    mov     qword ptr [rdi+16], r10
    mov     qword ptr [rdi+24], r11

    pop     rdi
    pop     rsi
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
jpssl_p256_neg ENDP
END
