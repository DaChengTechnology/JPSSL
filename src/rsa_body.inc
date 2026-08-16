// rsa_body.inc - RSA 澶ф暣鏁拌繍绠楀畯妯℃澘
// 浣跨敤鍓嶉渶瀹氫箟: K, BN, PUB_KEY, PRIV_KEY, CTX, MONT_CTX
// BN = rsa_bignum / rsa4096_bignum
// K = 32 / 64
// 棰勫埗绱犳暟琛?(浠呭厹搴曠敤閫? 绱犳暟鎼滅储瓒呮椂 100ms 鏃堕殢鏈哄彇鐢? 鍏紑绱犳暟, 娴嬭瘯鐜浣跨敤)
extern const uint64_t kPrebuiltPrimes1024[50][2][16];
extern const uint64_t kPrebuiltPrimes2048[50][2][32];

BN::BN(){zero();}
void BN::zero(){memset(d,0,sizeof(d));}
bool BN::is_zero()const{for(int i=0;i<K;++i)if(d[i])return 0;return 1;}
bool BN::is_one()const{if(d[0]!=1)return 0;for(int i=1;i<K;++i)if(d[i])return 0;return 1;}
int BN::bit_length()const{for(int i=K-1;i>=0;--i){if(d[i]){uint64_t t=d[i];int b=64;while(t){t>>=1;--b;}return(i+1)*64-b;}}return 0;}
bool BN::operator==(const BN&o)const{return memcmp(d,o.d,sizeof(d))==0;}
bool BN::operator<(const BN&o)const{for(int i=K-1;i>=0;--i)if(d[i]!=o.d[i])return d[i]<o.d[i];return 0;}
bool BN::bit(int p)const{return(d[p/64]>>(p%64))&1;}
void BN::set_bit(int p){d[p/64]|=(uint64_t)1<<(p%64);}
BN BN::from_uint64(uint64_t v){BN r;r.d[0]=v;return r;}
BN BN::from_bytes(const uint8_t*data,size_t len){BN r;r.zero();if(len>sizeof(r.d))len=sizeof(r.d);for(size_t i=0;i<len;++i)r.d[i/8]|=(uint64_t)data[len-1-i]<<((i%8)*8);return r;}
void BN::to_bytes(uint8_t*out)const{size_t bl=K*8;memset(out,0,bl);for(size_t i=0;i<bl;++i)out[bl-1-i]=(uint8_t)(d[i/8]>>((i%8)*8));}
BN BN::random_odd(){BN r;secure_rand_bytes(reinterpret_cast<uint8_t*>(r.d),sizeof(r.d));r.d[K-1]|=(uint64_t)1<<63;r.d[0]|=1;return r;}

void bn_add(BN&r,const BN&a,const BN&b){uint64_t c=0;for(int i=0;i<K;++i){uint64_t s=a.d[i]+b.d[i]+c;c=(s<a.d[i])?1:0;r.d[i]=s;}}
void bn_sub(BN&r,const BN&a,const BN&b){uint64_t bo=0;for(int i=0;i<K;++i){uint64_t sb=b.d[i]+bo;bo=(sb<b.d[i])?1:(a.d[i]<sb)?1:0;uint64_t df=a.d[i]-sb;r.d[i]=df;}}
void bn_mul(BN&r,const BN&a,const BN&b){BN t;for(int i=0;i<K;++i){if(!a.d[i])continue;uint64_t ca=0;for(int j=0;j<K-i;++j){__uint128_t p=(__uint128_t)a.d[i]*b.d[j]+t.d[i+j]+ca;t.d[i+j]=(uint64_t)p;ca=(uint64_t)(p>>64);}}r=t;}

void bn_divmod(BN&q,BN&r,const BN&a,const BN&b){r=a;q.zero();if(b.is_zero()||r<b)return;int sh=a.bit_length()-b.bit_length();BN bs;bn_lshift(bs,b,sh);for(int i=sh;i>=0;--i){if(!(r<bs)){bn_sub(r,r,bs);q.set_bit(i);}bn_rshift(bs,bs,1);}}
void bn_mod(BN&r,const BN&a,const BN&m){BN q;bn_divmod(q,r,a,m);}

void bn_rshift(BN&r,const BN&a,int bits){BN src=a;r.zero();int ws=bits/64,bs=bits%64;for(int i=0;i<K-ws;++i){r.d[i]=src.d[i+ws]>>bs;if(bs&&i+ws+1<K)r.d[i]|=src.d[i+ws+1]<<(64-bs);}}
void bn_lshift(BN&r,const BN&a,int bits){BN src=a;r.zero();int ws=bits/64,bs=bits%64;for(int i=K-1;i>=ws;--i){r.d[i]=src.d[i-ws]<<bs;if(bs&&i-ws>0)r.d[i]|=src.d[i-ws-1]>>(64-bs);}}

static uint64_t CAT(mont_mp_,K)(const BN&m){uint64_t m0=m.d[0],x=1;for(int i=0;i<63;++i)x=x*(2-m0*x);return(uint64_t)(-(int64_t)x);}
static void CAT(mont_mul_,K)(BN&r,const BN&a,const BN&b,const BN&m,uint64_t mp){
    // -- x86-64 fast path (MULX, K=32/64 only) --
    //    GCC/Clang: 鍐呰仈姹囩紪; MSVC: MASM 姹囩紪 (rsa_mont_asm_win.asm)
#if (defined(__x86_64__) || defined(_M_X64)) && (K == 32 || K == 64)
    if (mont_mul_asm_available()) {
        mont_mul_asm(r.d, a.d, b.d, m.d, mp, K);
        return;
    }
#endif
    uint64_t t[2*K+2]={};
    for(int i=0;i<K;++i){
#ifdef _MSC_VER
        // MSVC: 鐢ㄦ墜鍐?_umul128/_addcarry_u64 娑堥櫎 jp_uint128 涓存椂瀵硅薄寮€閿€
        uint64_t ca=0;
        for(int j=0;j<K;++j){
            uint64_t lo,hi;
            lo=_umul128(a.d[i],b.d[j],&hi);
            unsigned char cf1=_addcarry_u64(0,lo,(unsigned long long)t[i+j],&lo);
            unsigned char cf2=_addcarry_u64(0,lo,ca,&lo);
            hi+=(uint64_t)cf1+(uint64_t)cf2;
            t[i+j]=lo;ca=hi;
        }
        {
            unsigned char cf=_addcarry_u64(0,(unsigned long long)t[i+K],ca,&t[i+K]);
            if(cf){for(int j=i+K+1;;++j){uint64_t s2=t[j]+1;t[j]=s2;if(s2)break;}}
        }
        uint64_t u=t[i]*mp;ca=0;
        for(int j=0;j<K;++j){
            uint64_t lo,hi;
            lo=_umul128(u,m.d[j],&hi);
            unsigned char cf1=_addcarry_u64(0,lo,(unsigned long long)t[i+j],&lo);
            unsigned char cf2=_addcarry_u64(0,lo,ca,&lo);
            hi+=(uint64_t)cf1+(uint64_t)cf2;
            t[i+j]=lo;ca=hi;
        }
        for(int j=i+K;ca;++j){
            unsigned char cf=_addcarry_u64(0,(unsigned long long)t[j],ca,&t[j]);
            ca=(uint64_t)cf;
        }
#else
        uint64_t ca=0;
        for(int j=0;j<K;++j){
            __uint128_t p=(__uint128_t)a.d[i]*b.d[j]+t[i+j]+ca;
            t[i+j]=(uint64_t)p;ca=(uint64_t)(p>>64);
        }
        uint64_t sc=t[i+K]+ca;t[i+K]=sc;
        if(sc<ca){for(int j=i+K+1;;++j){uint64_t s2=t[j]+1;t[j]=s2;if(s2)break;}}
        uint64_t u=t[i]*mp;ca=0;
        for(int j=0;j<K;++j){
            __uint128_t s=(__uint128_t)u*m.d[j]+t[i+j]+ca;
            t[i+j]=(uint64_t)s;ca=(uint64_t)(s>>64);
        }
        for(int j=i+K;ca;++j){
            __uint128_t s=(__uint128_t)t[j]+ca;
            t[j]=(uint64_t)s;ca=(uint64_t)(s>>64);
        }
#endif
    }
    for(int i=0;i<K;++i)r.d[i]=t[i+K];
    if(t[2*K]){bn_sub(r,r,m);if(!(r<m))bn_sub(r,r,m);}
    BN mc=m;while(!(r<mc))bn_sub(r,r,m);
}
// 鈹€鈹€ 鍗婂昂瀵?Montgomery 涔樻硶: 鍙鐞嗗墠 K/2 limb (CRT 鐨?p/q 妯″箓涓撶敤) 鈹€鈹€
static void CAT(mont_mul_half_,K)(BN&r,const BN&a,const BN&b,const BN&m,uint64_t mp){
    const int HK=K/2;
    // -- x86-64 fast path (MULX, HK=16/32 only, 涓?mont_mul_ 鍚岃皟搴? --
    //    GCC/Clang: 鍐呰仈姹囩紪; MSVC: MASM 姹囩紪 (rsa_mont_asm_win.asm)
    //    姹囩紪鐗堣嚜韬礋璐ｉ珮浣?r[HK..2HK-1] 娓呴浂 (鍗婂昂瀵歌緭鍑鸿涔?
#if (defined(__x86_64__) || defined(_M_X64)) && (K == 32 || K == 64)
    if (mont_mul_asm_available()) {
        mont_mul_half_asm(r.d, a.d, b.d, m.d, mp, HK);
        return;
    }
#endif
    uint64_t t[K+2]={};   // 2*HK+2
    for(int i=0;i<HK;++i){
#ifdef _MSC_VER
        uint64_t ca=0;
        for(int j=0;j<HK;++j){
            uint64_t lo,hi;
            lo=_umul128(a.d[i],b.d[j],&hi);
            unsigned char cf1=_addcarry_u64(0,lo,(unsigned long long)t[i+j],&lo);
            unsigned char cf2=_addcarry_u64(0,lo,ca,&lo);
            hi+=(uint64_t)cf1+(uint64_t)cf2;
            t[i+j]=lo;ca=hi;
        }
        {
            unsigned char cf=_addcarry_u64(0,(unsigned long long)t[i+HK],ca,&t[i+HK]);
            if(cf){int j=i+HK+1;for(;j<K+2;++j){uint64_t s2=t[j]+1;t[j]=s2;if(s2)break;}
                    if(j>=K+2)fprintf(stderr,"[mmh] PROP1 OOB i=%d\n",i);}
        }
        uint64_t u=t[i]*mp;ca=0;
        for(int j=0;j<HK;++j){
            uint64_t lo,hi;
            lo=_umul128(u,m.d[j],&hi);
            unsigned char cf1=_addcarry_u64(0,lo,(unsigned long long)t[i+j],&lo);
            unsigned char cf2=_addcarry_u64(0,lo,ca,&lo);
            hi+=(uint64_t)cf1+(uint64_t)cf2;
            t[i+j]=lo;ca=hi;
        }
        for(int j=i+HK;ca;++j){
            if(j>=K+2){fprintf(stderr,"[mmh] PROP2 OOB i=%d\n",i);ca=0;break;}
            unsigned char cf=_addcarry_u64(0,(unsigned long long)t[j],ca,&t[j]);
            ca=(uint64_t)cf;
        }
#else
        uint64_t ca=0;
        for(int j=0;j<HK;++j){
            __uint128_t p=(__uint128_t)a.d[i]*b.d[j]+t[i+j]+ca;
            t[i+j]=(uint64_t)p;ca=(uint64_t)(p>>64);
        }
        uint64_t sc=t[i+HK]+ca;t[i+HK]=sc;
        if(sc<ca){for(int j=i+HK+1;;++j){uint64_t s2=t[j]+1;t[j]=s2;if(s2)break;}}
        uint64_t u=t[i]*mp;ca=0;
        for(int j=0;j<HK;++j){
            __uint128_t s=(__uint128_t)u*m.d[j]+t[i+j]+ca;
            t[i+j]=(uint64_t)s;ca=(uint64_t)(s>>64);
        }
        for(int j=i+HK;ca;++j){
            __uint128_t s=(__uint128_t)t[j]+ca;
            t[j]=(uint64_t)s;ca=(uint64_t)(s>>64);
        }
#endif
    }
    for(int i=0;i<HK;++i)r.d[i]=t[i+HK];
    for(int i=HK;i<K;++i)r.d[i]=0;   // 楂樹綅娓呴浂 (鏉′欢鍑忔硶姣旇緝渚濊禆)
    // 鏉′欢鍑忔硶 (鍗婂昂瀵?: 杈撳嚭 = r + t[2*HK]*2^(HK*64) < 2m
    // 蹇呴』鐢?HK-limb 鍑忔硶 (妯?2^(HK*64)): 鍏ㄥ昂瀵?bn_sub 鏄ā 2^(K*64),
    // t[2*HK]=1 涓?r<m 鏃跺€熶綅浼氬惊鐜垚 r-m+2^(K*64) 鐨勫法澶ч敊璇€?
#if defined(_MSC_VER) && !defined(__clang__)
    if(t[2*HK]){unsigned char bo=0;for(int i=0;i<HK;++i)bo=_subborrow_u64(bo,r.d[i],m.d[i],&r.d[i]);}
    int guard=0;while(!(r<m)&&guard++<32){unsigned char bo=0;for(int i=0;i<HK;++i)bo=_subborrow_u64(bo,r.d[i],m.d[i],&r.d[i]);}
#else
    if(t[2*HK]){uint64_t bo=0;for(int i=0;i<HK;++i){uint64_t sb=m.d[i]+bo;bo=(sb<m.d[i])?1:(r.d[i]<sb)?1:0;r.d[i]-=sb;}}
    int guard=0;while(!(r<m)&&guard++<32){uint64_t bo=0;for(int i=0;i<HK;++i){uint64_t sb=m.d[i]+bo;bo=(sb<m.d[i])?1:(r.d[i]<sb)?1:0;r.d[i]-=sb;}}
#endif
    if(!(r<m))fprintf(stderr,"[mmh] SUB FAIL hi=%016llx t2hk=%d\n",(unsigned long long)r.d[K-1],(int)t[2*HK]);
}
// 鈹€鈹€ 鍗婂昂瀵?8-bit 绐楀彛 Montgomery 妯″箓 (CRT 鐨?m1/m2: 妯℃暟涓?p/q) 鈹€鈹€
// 8-bit 绐楀彛: bits 娆″钩鏂?+ bits/8 娆′箻娉?+ 254 娆￠璁＄畻
static void CAT(compute_2exp_mod_,K)(BN&r,const BN&base,uint64_t exp,const BN&m);
// ??? 8-bit ?? Montgomery ?? (p/q ????): ????, R_half/R2_half ??????
static void CAT(mont_modpow_half_win8_ex_,K)(BN&r,const BN&base,const BN&exp,const MONT_CTX&mc,const BN&mod,
                                             const BN&R_half,const BN&R2_half){
    const int HK=K/2;
    if(mod.is_zero()){r.zero();return;}
    if(exp.is_zero()){r=BN::from_uint64(1);return;}
    BN b0=base;if(!(b0<mod))bn_mod(b0,base,mod);   // reduce base < mod
    BN one=BN::from_uint64(1);
    BN bm;CAT(mont_mul_half_,K)(bm,b0,R2_half,mod,mc.m_prime);   // to_mont (half domain)
    BN win[256];
    win[0]=R_half;
    win[1]=bm;
    for(int j=2;j<256;++j)CAT(mont_mul_half_,K)(win[j],win[j-1],bm,mod,mc.m_prime);
    int bits=exp.bit_length();
    BN rm=R_half;
    int i=bits-1;
    int fc=(bits%8==0)?8:(bits%8);
    {int idx=0;for(int k=0;k<fc;++k)idx=(idx<<1)|(exp.bit(i-k)?1:0);
     for(int k=0;k<fc;++k)CAT(mont_mul_half_,K)(rm,rm,rm,mod,mc.m_prime);
     if(idx)CAT(mont_mul_half_,K)(rm,rm,win[idx],mod,mc.m_prime);}
    i-=fc;
    for(;i>=7;i-=8){
        for(int k=0;k<8;++k)CAT(mont_mul_half_,K)(rm,rm,rm,mod,mc.m_prime);
        int chunk=0;
        for(int k=0;k<8;++k)chunk=(chunk<<1)|(exp.bit(i-k)?1:0);
        if(chunk)CAT(mont_mul_half_,K)(rm,rm,win[chunk],mod,mc.m_prime);
    }
    if(i>=0){
        for(int k=0;k<=i;++k)CAT(mont_mul_half_,K)(rm,rm,rm,mod,mc.m_prime);
        int chunk=0;
        for(int k=0;k<=i;++k)chunk=(chunk<<1)|(exp.bit(k)?1:0);
        if(chunk)CAT(mont_mul_half_,K)(rm,rm,win[chunk],mod,mc.m_prime);
    }
    CAT(mont_mul_half_,K)(r,rm,one,mod,mc.m_prime);   // from_mont (half domain)
}
// R_half/R2_half ?????: ???? (p/q) ????, ???????????;
// ??????? (MR ??????, ?????); ????? + 8 ???
struct CAT(half_rh_,K){BN R_half,R2_half;};
static CAT(half_rh_,K) CAT(g_half_rh_,K)[8];
static BN CAT(g_half_rh_mod_,K)[8];
static int CAT(g_half_rh_next_,K)=0;
static std::atomic_flag CAT(g_half_rh_lock_,K)=ATOMIC_FLAG_INIT;
static void CAT(half_rh_get_,K)(const BN&mod,BN&R_half,BN&R2_half){
    while(CAT(g_half_rh_lock_,K).test_and_set(std::memory_order_acquire)){}
    for(int i=0;i<8;++i)
        if(CAT(g_half_rh_mod_,K)[i]==mod){
            std::memcpy(R_half.d,CAT(g_half_rh_,K)[i].R_half.d,sizeof(uint64_t)*K);
            std::memcpy(R2_half.d,CAT(g_half_rh_,K)[i].R2_half.d,sizeof(uint64_t)*K);
            CAT(g_half_rh_lock_,K).clear(std::memory_order_release);return;}
    int slot=CAT(g_half_rh_next_,K)++;if(slot>=8)slot=0;
    BN one=BN::from_uint64(1);
    CAT(compute_2exp_mod_,K)(R_half,one,(uint64_t)((K/2)*64),mod);
    CAT(compute_2exp_mod_,K)(R2_half,R_half,(uint64_t)((K/2)*64),mod);
    std::memcpy(CAT(g_half_rh_mod_,K)[slot].d,mod.d,sizeof(uint64_t)*K);
    std::memcpy(CAT(g_half_rh_,K)[slot].R_half.d,R_half.d,sizeof(uint64_t)*K);
    std::memcpy(CAT(g_half_rh_,K)[slot].R2_half.d,R2_half.d,sizeof(uint64_t)*K);
    CAT(g_half_rh_lock_,K).clear(std::memory_order_release);
}
// ????: ???? R_half/R2_half (MR/?????, ??????)
static void CAT(mont_modpow_half_win8_,K)(BN&r,const BN&base,const BN&exp,const MONT_CTX&mc,const BN&mod){
    BN one=BN::from_uint64(1),R_half,R2_half;
    CAT(compute_2exp_mod_,K)(R_half,one,(uint64_t)((K/2)*64),mod);
    CAT(compute_2exp_mod_,K)(R2_half,R_half,(uint64_t)((K/2)*64),mod);
    CAT(mont_modpow_half_win8_ex_,K)(r,base,exp,mc,mod,R_half,R2_half);
}
// ????: R_half/R2_half ??????
static void CAT(mont_modpow_half_win8_cached_,K)(BN&r,const BN&base,const BN&exp,const MONT_CTX&mc,const BN&mod){
    BN R_half,R2_half;
    CAT(half_rh_get_,K)(mod,R_half,R2_half);
    CAT(mont_modpow_half_win8_ex_,K)(r,base,exp,mc,mod,R_half,R2_half);
}
static void CAT(to_mont_,K)(BN&r,const BN&a,const BN&m,const BN&R2,uint64_t mp){CAT(mont_mul_,K)(r,a,R2,m,mp);}
static void CAT(from_mont_,K)(BN&r,const BN&a,const BN&m,uint64_t mp){BN one=BN::from_uint64(1);CAT(mont_mul_,K)(r,a,one,m,mp);}

// 璁＄畻 base * 2^exp mod m, 鐢ㄩ€?bit 宸︾Щ+鍙栨ā
// 娉ㄦ剰: bn_lshift 宸︾Щ1浣嶅綋鏈€楂樹綅涓?鏃朵細涓㈠け婧㈠嚭浣?// 鎵€浠ョ敤鏉′欢鍑忔硶: 濡傛灉 r > m/2, 鍒?2r >= m, 鐢?r-(m-r)=2r-m 閬垮厤婧㈠嚭
static void CAT(compute_2exp_mod_,K)(BN&r,const BN&base,uint64_t exp,const BN&m){
  r=base;
  BN half_m;bn_rshift(half_m,m,1);
  for(uint64_t i=0;i<exp;++i){
    // 不变量：r < m。三分支：r < m/2 直接左移（不溢出，因 r < 2^(K*64-1)）；
    // r == m/2 时 2r = m → 0；r > m/2 时 2r mod m = 2r - m = r - (m - r)（避免溢出）
    if(r<half_m){
      BN tmp;bn_lshift(tmp,r,1);
      r=tmp;
    } else if(r==half_m){
      r.zero();
    } else {
      BN diff;bn_sub(diff,m,r);
      bn_sub(r,r,diff);
    }
  }
}
static MONT_CTX CAT(mont_init_,K)(const BN&m){
  MONT_CTX c;c.m_prime=CAT(mont_mp_,K)(m);
  BN one=BN::from_uint64(1);
  CAT(compute_2exp_mod_,K)(c.R_mod_m,one,(uint64_t)(K*64),m);
  CAT(compute_2exp_mod_,K)(c.R2_mod_m,c.R_mod_m,(uint64_t)(K*64),m);
  return c;
}

// 涓嶆埅鏂殑澶ф暟涔樻硶鍙栨ā: r = (a*b) mod m, 鐢?2K-limb 涓存椂鏁扮粍閬垮厤鎴柇
static void CAT(bn_mulmod_,K)(BN&r,const BN&a,const BN&b,const BN&m){
  uint64_t t[2*K]={};
  for(int i=0;i<K;++i){if(!a.d[i])continue;uint64_t ca=0;for(int j=0;j<K;++j){__uint128_t p=(__uint128_t)a.d[i]*b.d[j]+t[i+j]+ca;t[i+j]=(uint64_t)p;ca=(uint64_t)(p>>64);}t[i+K]=ca;}
  // 閫?limb 鍙栨ā: rem = (rem << 64 | t[i]) mod m, 浠庨珮鍒颁綆
  BN rem;rem.zero();
  for(int i=2*K-1;i>=0;--i){
    CAT(compute_2exp_mod_,K)(rem,rem,64,m);
    if(t[i]){
      BN ti=BN::from_uint64(t[i]);
      // 淇: ti 鏄畬鏁?64-bit limb 鍙兘 > m. (rem+ti) mod m:
      // rem < m, ti < 2^64 鈫?sum = rem+ti < 2^64 + m < 2m (褰?m > 2^64, 鍗?鈮?025-bit)
      // 浠呭綋 sum >= m 鏃跺彇妯? 灏忔ā鏁颁笅 sum 鍙兘 鈮?2m, bn_mod 鍏滃簳
      BN sum;bn_add(sum,rem,ti);
      if(sum<m){rem=sum;}
      else bn_mod(rem,sum,m);
    }
  }
  r=rem;
}

void bn_modpow(BN&r,const BN&base,const BN&exp,const BN&mod){
  if(mod.is_zero()){r.zero();return;}
  // Montgomery 模幂：mont_init 依赖的 compute_2exp_mod_ 已修复 r==m/2 边界
  // （2079663 三分支），故可安全回到 Montgomery 路径，避免朴素平方-乘的
  // 慢速全模幂（RSA-2048 实测 456ms → ~1ms）。exp=0 时循环不执行，
  // from_mont(R_mod_m) 恰好返回 1。
  MONT_CTX mc=CAT(mont_init_,K)(mod);
  BN b0=base;if(!(b0<mod))bn_mod(b0,base,mod);
  BN bm;CAT(to_mont_,K)(bm,b0,mod,mc.R2_mod_m,mc.m_prime);
  BN rm=mc.R_mod_m;
  int bits=exp.bit_length();
  for(int i=bits-1;i>=0;--i){
    CAT(mont_mul_,K)(rm,rm,rm,mod,mc.m_prime);
    if(exp.bit(i))CAT(mont_mul_,K)(rm,rm,bm,mod,mc.m_prime);
  }
  CAT(from_mont_,K)(r,rm,mod,mc.m_prime);
}


// 4-bit 鍥哄畾绐楀彛 Montgomery 妯″箓 (鎸囨暟绐楀彛鍖? 鍑忓皯 mont_mul 娆℃暟)
//  浜岃繘鍒?  bits 娆″钩鏂?+ ~bits/2 娆′箻娉?鈮?3072 娆?mont_mul (2048-bit)
//  4-bit 绐楀彛: bits 娆″钩鏂?+ bits/4 娆′箻娉?+ 14 娆￠璁＄畻 鈮?2574 娆?mont_mul (~16% 鏇村皯)
void CAT(mont_modpow_win_fn_,K)(BN&r,const BN&base,const BN&exp,const MONT_CTX&mc,const BN&mod){
    if(mod.is_zero()){r.zero();return;}
    if(exp.is_zero()){r=BN::from_uint64(1);return;}
    // to_mont (base 鍏堢害鍑忓埌 < mod; 钂欏摜椹埄杈撳叆绾﹀畾, CRT 瑙ｅ瘑浼氫紶 c>=p)
    BN b0=base;if(!(b0<mod))bn_mod(b0,base,mod);
    BN bm;CAT(to_mont_,K)(bm,b0,mod,mc.R2_mod_m,mc.m_prime);
    // 棰勮绠楃獥鍙ｈ〃 win[0..15]: win[0]=1(mont), win[j]=base^j
    BN win[16];
    win[0]=mc.R_mod_m;
    win[1]=bm;
    for(int j=2;j<16;++j)CAT(mont_mul_,K)(win[j],win[j-1],bm,mod,mc.m_prime);
    // MSB 浼樺厛, 4-bit 鍧?
    int bits=exp.bit_length();
    BN rm=mc.R_mod_m;
    int i=bits-1;
    // 棣栦釜涓嶅畬鏁村潡 (bits%4)
    int fc = (bits%4==0)?4:(bits%4);
    {int idx=0;for(int k=0;k<fc;++k)idx=(idx<<1)|(exp.bit(i-k)?1:0);
     for(int k=0;k<fc;++k)CAT(mont_mul_,K)(rm,rm,rm,mod,mc.m_prime);
     if(idx)CAT(mont_mul_,K)(rm,rm,win[idx],mod,mc.m_prime);}
    i-=fc;
    // 瀹屾暣 4-bit 鍧?
    for(;i>=3;i-=4){
        for(int k=0;k<4;++k)CAT(mont_mul_,K)(rm,rm,rm,mod,mc.m_prime);
        int chunk=0;
        for(int k=0;k<4;++k)chunk=(chunk<<1)|(exp.bit(i-k)?1:0);
        if(chunk)CAT(mont_mul_,K)(rm,rm,win[chunk],mod,mc.m_prime);
    }
    // 灏鹃儴娈嬬暀 (0-3 bit)
    if(i>=0){
        for(int k=0;k<=i;++k)CAT(mont_mul_,K)(rm,rm,rm,mod,mc.m_prime);
        int chunk=0;
        for(int k=0;k<=i;++k)chunk=(chunk<<1)|(exp.bit(k)?1:0);
        if(chunk)CAT(mont_mul_,K)(rm,rm,win[chunk],mod,mc.m_prime);
    }
    CAT(from_mont_,K)(r,rm,mod,mc.m_prime);
}

MONT_CTX CAT(mont_init_fn_,K)(const BN&m){return CAT(mont_init_,K)(m);}
// 半宽路径专用: 只需 m_prime, 跳过 R_mod_m/R2_mod_m 的 2*K*64 次移位取模预计算
// (mont_modpow_half_win8_ 内部会自算 R_half/R2_half)
static MONT_CTX CAT(mont_init_mp_,K)(const BN&m){MONT_CTX c;c.m_prime=CAT(mont_mp_,K)(m);return c;}
// 全尺寸 R/R2 按模数缓存: 公钥加密/验签等固定模数重复使用只算一次,
// 省掉 mont_init_ 里 2*K*64 次移位取模 (2048 加密的主要开销); 8 槽轮换 + 自旋锁
struct CAT(full_rh_,K){BN R,R2;};
static CAT(full_rh_,K) CAT(g_full_rh_,K)[8];
static BN CAT(g_full_rh_mod_,K)[8];
static int CAT(g_full_rh_next_,K)=0;
static std::atomic_flag CAT(g_full_rh_lock_,K)=ATOMIC_FLAG_INIT;
static void CAT(full_rh_get_,K)(const BN&mod,BN&R,BN&R2){
    while(CAT(g_full_rh_lock_,K).test_and_set(std::memory_order_acquire)){}
    for(int i=0;i<8;++i)
        if(CAT(g_full_rh_mod_,K)[i]==mod){
            std::memcpy(R.d,CAT(g_full_rh_,K)[i].R.d,sizeof(uint64_t)*K);
            std::memcpy(R2.d,CAT(g_full_rh_,K)[i].R2.d,sizeof(uint64_t)*K);
            CAT(g_full_rh_lock_,K).clear(std::memory_order_release);return;}
    int slot=CAT(g_full_rh_next_,K)++;if(slot>=8)slot=0;
    BN one=BN::from_uint64(1);
    CAT(compute_2exp_mod_,K)(R,one,(uint64_t)(K*64),mod);
    CAT(compute_2exp_mod_,K)(R2,R,(uint64_t)(K*64),mod);
    std::memcpy(CAT(g_full_rh_mod_,K)[slot].d,mod.d,sizeof(uint64_t)*K);
    std::memcpy(CAT(g_full_rh_,K)[slot].R.d,R.d,sizeof(uint64_t)*K);
    std::memcpy(CAT(g_full_rh_,K)[slot].R2.d,R2.d,sizeof(uint64_t)*K);
    CAT(g_full_rh_lock_,K).clear(std::memory_order_release);
}
// Montgomery 上下文初始化 (R/R2 走缓存; 固定公钥重复加密时仅首次计算)
static MONT_CTX CAT(mont_init_cached_,K)(const BN&m){
    MONT_CTX c;c.m_prime=CAT(mont_mp_,K)(m);
    CAT(full_rh_get_,K)(m,c.R_mod_m,c.R2_mod_m);
    return c;
}
void CAT(mont_modpow_fn_,K)(BN&r,const BN&base,const BN&exp,const MONT_CTX&mc,const BN&mod){if(mod.is_zero()){r.zero();return;}BN b0=base;if(!(b0<mod))bn_mod(b0,base,mod);BN bm;CAT(to_mont_,K)(bm,b0,mod,mc.R2_mod_m,mc.m_prime);BN rm=mc.R_mod_m;int bits=exp.bit_length();for(int i=bits-1;i>=0;--i){CAT(mont_mul_,K)(rm,rm,rm,mod,mc.m_prime);if(exp.bit(i))CAT(mont_mul_,K)(rm,rm,bm,mod,mc.m_prime);}CAT(from_mont_,K)(r,rm,mod,mc.m_prime);}

// 澶ф暟瀵瑰皬绱犳暟鍙栨ā (p < 2^32), O(K) 閫?limb
static uint32_t CAT(bn_mod_small_,K)(const BN&n,uint32_t p){uint64_t r=0;for(int i=K-1;i>=0;--i){__uint128_t t=((__uint128_t)r<<64)|n.d[i];r=(uint64_t)(t%p);}return(uint32_t)r;}
// 灏忕礌鏁拌瘯闄よ〃 (3..~3600, 绾?500 涓礌鏁?, 棣栨璋冪敤鏃剁敤绛涙硶鐢熸垚
static const uint32_t* CAT(get_small_primes_,K)(size_t&cnt){static uint32_t tbl[512];static bool sieve[3601]={};static size_t nn=0;if(nn==0){for(int i=2;i<=3600;++i)if(!sieve[i]){if(i>2)tbl[nn++]=(uint32_t)i;for(int j=i*2;j<=3600;j+=i)sieve[j]=1;}}cnt=nn;return tbl;}
// 鎵╁睍灏忕礌鏁拌〃 (3..65521, 6542 涓?: 浠?keygen 澧為噺绛涗娇鐢?
// 鎶?MR 鍊欓€夎繃婊ょ巼浠?~13% (<=3600) 闄嶅埌 ~5%, MR 娆℃暟鍑忓崐浠ヤ笂
static const uint32_t* CAT(get_sieve_primes_,K)(size_t&cnt){static uint32_t tbl[6600];static bool sieve[65522]={};static size_t nn=0;if(nn==0){for(int i=2;i<=65521;++i)if(!sieve[i]){if(i>2)tbl[nn++]=(uint32_t)i;for(int j=i*2;j<=65521;j+=i)sieve[j]=1;}}cnt=nn;return tbl;}
// MR 杞暟: 涓?OpenSSL BN_prime_checks_for_size 瀵归綈 (1024-bit 绱犳暟 40 杞? 2048-bit 64 杞?
static int CAT(mr_rounds_,K)(){return K>=64?64:40;}
// OpenMP 并行度: 4096 占满全部逻辑核 (可用 OMP_NUM_THREADS 覆盖), 2048 用 8 线程
// 足够 (工作量小, 团队创建开销占比高); 上限 32
static int CAT(mr_workers_,K)(){
#ifdef _OPENMP
    int w=omp_get_max_threads();
    int cap=(K>=64)?24:8;
    if(w>cap)w=cap;if(w<1)w=1;return w;
#else
    return 1;
#endif
}
static bool CAT(bn_is_prime_impl_,K)(const BN&n,int rounds,bool sieve_done){
  if(n.is_zero()||n.is_one())return 0;
  if(n.d[0]%2==0)return n.d[0]==2;
  if(!sieve_done){
  // 灏忕礌鏁拌瘯闄ら绛? 杩囨护鎺夎灏忕礌鏁版暣闄ょ殑鍚堟暟鍊欓€?(OpenMP 骞惰, 鍚勭礌鏁扮嫭绔?
  // has_factor: 0=鏈煡, 1=鍚堟暟(鏈夌湡鍥犲瓙), 2=n 鏈韩灏辨槸璇ョ礌鏁?
  size_t sp_cnt;const uint32_t*sp=CAT(get_small_primes_,K)(sp_cnt);
  for(size_t i=0;i<sp_cnt;++i){
    uint32_t p=sp[i];uint32_t r=CAT(bn_mod_small_,K)(n,p);
    if(r==0){
      bool self=1;for(int j=1;j<K;++j)if(n.d[j]){self=0;break;}
      if(self&&n.d[0]==p)return 1;
      return 0;
    }
  }
  }
  // Miller-Rabin: 棰勮绠?Montgomery 涓婁笅鏂? rounds 杞彧鍒濆鍖栦竴娆?
  BN n1,d;bn_sub(n1,n,BN::from_uint64(1));d=n1;int s=0;
  while(d.d[0]%2==0){bn_rshift(d,d,1);++s;}
  bool half=1;for(int i=K/2;i<K;++i)if(n.d[i]){half=0;break;}
  MONT_CTX mc=half?CAT(mont_init_mp_,K)(n):CAT(mont_init_,K)(n);
  // 鍗婂璺緞: n 鍙崰 K/2 limb (1024/2048-bit 绱犳暟) 鏃剁敤鍗婂 Montgomery 妯″箓,
  // MR 鍗曡疆鎴愭湰绾﹂檷 2.6x (keygen 绱犳暟鎼滅储鐨勪富瑕佸紑閿€)
  // Miller-Rabin: one Montgomery ctx for all rounds; run rounds in wide batches
  // with OpenMP (mr_workers_ threads, independent random bases, one half-width
  // modpow per thread), saturating all cores; serial fallback when OpenMP is off.
  // Note: primes occupy K/2 limbs, the modulus cannot shrink further
  // (quarter width cannot hold it) -- the speedup is wide parallel batches.
#ifdef _OPENMP
  {int W=CAT(mr_workers_,K)();if(W>rounds)W=rounds;if(W<1)W=1;
  for(int k=0;k<rounds;k+=W){
    int batch=rounds-k;if(batch>W)batch=W;
    bool comp[32]={};
    int j;
#pragma omp parallel for num_threads(W) schedule(static)
    for(j=0;j<batch;++j){
      BN a=BN::random_odd();bn_mod(a,a,n);
      if(a.is_zero()||a.is_one()||a==n1)continue;
      BN x;
      if(half) CAT(mont_modpow_half_win8_,K)(x,a,d,mc,n);
      else if(d.bit_length() >= 64) CAT(mont_modpow_win_fn_,K)(x,a,d,mc,n);
      else CAT(mont_modpow_fn_,K)(x,a,d,mc,n);
      if(x.is_one()||x==n1)continue;
      bool c=1;
      for(int r=0;r<s-1;++r){BN t;CAT(bn_mulmod_,K)(t,x,x,n);if(t==n1){c=0;break;}x=t;}
      comp[j]=c;
    }
    for(int j2=0;j2<batch;++j2)if(comp[j2])return 0;
  }
  }
#else
  for(int k=0;k<rounds;++k){
    BN a=BN::random_odd();bn_mod(a,a,n);if(a.is_zero()||a.is_one()||a==n1)continue;
    BN x;
    if(half) CAT(mont_modpow_half_win8_,K)(x,a,d,mc,n);
    else if(d.bit_length() >= 64) CAT(mont_modpow_win_fn_,K)(x,a,d,mc,n);
    else CAT(mont_modpow_fn_,K)(x,a,d,mc,n);
    if(x.is_one()||x==n1)continue;
    bool comp=1;
    for(int r=0;r<s-1;++r){BN t;CAT(bn_mulmod_,K)(t,x,x,n);if(t==n1){comp=0;break;}x=t;}
    if(comp)return 0;
  }
#endif
  return 1;
}
bool bn_is_prime(const BN&n,int rounds){return CAT(bn_is_prime_impl_,K)(n,rounds,false);}
// 蹇€熻矾寰? 璋冪敤鏂瑰凡鐢ㄥ閲忕瓫瀹屾垚鍏ㄩ儴灏忕礌鏁拌瘯闄? 璺宠繃鍐呴儴绛?
bool bn_is_prime_sieved(const BN&n,int rounds){return CAT(bn_is_prime_impl_,K)(n,rounds,true);}
// 单轮 Miller-Rabin 过滤 (kgen 攒批 4 候选并行使用; 不做小素数试除, 调用方已过筛)
// 返回 true 表示这一轮没有证伪 (可能仍为合数, 需完整轮数确认)
static bool CAT(mr_filter_,K)(const BN&n){
  BN n1,d;bn_sub(n1,n,BN::from_uint64(1));d=n1;int s=0;
  while(d.d[0]%2==0){bn_rshift(d,d,1);++s;}
  bool half=1;for(int i=K/2;i<K;++i)if(n.d[i]){half=0;break;}
  MONT_CTX mc=half?CAT(mont_init_mp_,K)(n):CAT(mont_init_,K)(n);
  BN a=BN::random_odd();bn_mod(a,a,n);
  if(a.is_zero()||a.is_one()||a==n1)return true;
  BN x;
  if(half) CAT(mont_modpow_half_win8_,K)(x,a,d,mc,n);
  else if(d.bit_length()>=64) CAT(mont_modpow_win_fn_,K)(x,a,d,mc,n);
  else CAT(mont_modpow_fn_,K)(x,a,d,mc,n);
  if(x.is_one()||x==n1)return true;
  for(int r=0;r<s-1;++r){BN t;CAT(bn_mulmod_,K)(t,x,x,n);if(t==n1)return true;x=t;}
  return false;
}
void bn_modinv(BN&r,const BN&a,const BN&m){
    // 鎵╁睍娆у嚑閲屽緱闄ゆ硶鐗? r0=m, r1=a, s0=0, s1=1
    // 绯绘暟鐢?(s0 - q*s1) mod m 鏇存柊 (q*s1 缁?bn_mulmod 鍙栨ā, 閬垮厤瓒?BN 瀹瑰櫒鎴柇)
    // 瀵逛换鎰?m (鍚伓鏁? 濡?RSA 鐨?phi) 鏈夋晥; 浜岃繘鍒剁増瑕佹眰 m 濂囨暟鏁呭純鐢?
    BN r0=m,r1=a,s0,s1=BN::from_uint64(1),q,rem,p,t;
    s0.zero();
    while(!r1.is_zero()){
        bn_divmod(q,rem,r0,r1);
        CAT(bn_mulmod_,K)(p,q,s1,m);   // p = q*s1 mod m
        BN s2;
        if(s0<p){bn_sub(t,p,s0);bn_sub(s2,m,t);}
        else bn_sub(s2,s0,p);
        r0=r1;r1=rem;
        s0=s1;s1=s2;
    }
    r=s0;
    if(!(r<m))bn_sub(r,r,m);
}

// 素数搜索: 随机奇数起点 (最高两位置 1, 保证 p*q 恒为满位宽) + 增量 +2,
// 对全部 6542 个小素数 (<=65521) 维护余数表 (O(1) 更新);
// 过筛候选 (且 gcd(p-1,e)==1, != avoid) 先入队, 攒满 W 个后用 OpenMP 全核
// 并行跑各自第 1 轮 MR 过滤, 幸存者再做完整 rounds 轮 (内部同样全核分批),
// 合数过滤阶段也获得 ~W 倍并行 (W = OMP_NUM_THREADS, 默认占满逻辑核)
static bool CAT(kgen_next_prime_,K)(BN& out, const BN& avoid, std::chrono::steady_clock::time_point deadline){
    size_t sp_cnt;const uint32_t* sp=CAT(get_sieve_primes_,K)(sp_cnt);
    const int rounds=CAT(mr_rounds_,K)();
    const int W=CAT(mr_workers_,K)();
    BN q4[32];int nq=0;bool s4[32];
    for(;;){
        out=BN::random_odd();
        for(int i=K/2;i<K;++i)out.d[i]=0;
        out.d[K/2-1]|=(uint64_t)1<<63;
        out.d[K/2-1]|=(uint64_t)1<<62;
        uint32_t rems[6600];
        for(size_t pi=0;pi<sp_cnt;++pi)rems[pi]=CAT(bn_mod_small_,K)(out,sp[pi]);
        for(int steps=0;steps<300000;++steps){
            if(std::chrono::steady_clock::now()>=deadline)return false;  // 超时 → 调用方兜底
            bool pass=1;
            for(size_t pi=0;pi<sp_cnt;++pi)if(rems[pi]==0){pass=0;break;}
            if(pass&&CAT(bn_mod_small_,K)(out,65537)!=1&&!(out==avoid)){
                q4[nq++]=out;
                if(nq==W){
#ifdef _OPENMP
                    int j;
#pragma omp parallel for num_threads(W) schedule(static)
                    for(j=0;j<W;++j)s4[j]=CAT(mr_filter_,K)(q4[j]);
#else
                    for(int j=0;j<W;++j)s4[j]=CAT(mr_filter_,K)(q4[j]);
#endif
                    for(int j=0;j<W;++j){
                        if(!s4[j])continue;
                        // 幸存者增量加轮: 1 + 7 + (rounds-8) = rounds, 假幸存者只付少量批次
                        if(!bn_is_prime_sieved(q4[j],7))continue;
                        if(bn_is_prime_sieved(q4[j],rounds-8)){out=q4[j];return true;}
                    }
                    nq=0;
                }
            }
            {uint64_t c=2;for(int i=0;i<K;++i){uint64_t s=out.d[i]+c;c=(s<out.d[i])?1:0;out.d[i]=s;if(!c)break;}}
            if(out.d[K/2]!=0)break;  // 溢出到上半区 → 重新随机起点
            for(size_t pi=0;pi<sp_cnt;++pi){rems[pi]+=2;if(rems[pi]>=sp[pi])rems[pi]-=sp[pi];}
        }
    }
}
// 棰勫埗绱犳暟鍏滃簳: slot=0 鍙?p, slot=1 鍙?q (绱㈠紩闅忔満, 閬垮厤姣忔鐩稿悓)
static void CAT(kgen_prebuilt_,K)(BN& out, int slot){
#if K == 32
    uint64_t idx=BN::random_odd().d[0]%50;
    std::memcpy(out.d,kPrebuiltPrimes1024[idx][slot],16*sizeof(uint64_t));
    for(int i=16;i<K;++i)out.d[i]=0;
#else
    uint64_t idx=BN::random_odd().d[0]%50;
    std::memcpy(out.d,kPrebuiltPrimes2048[idx][slot],32*sizeof(uint64_t));
    for(int i=32;i<K;++i)out.d[i]=0;
#endif
}

bool CAT(keygen_fn_,K)(PUB_KEY&pub,PRIV_KEY&prv){
    const auto t0=std::chrono::steady_clock::now();
    const auto timeout=std::chrono::milliseconds(K>=64?1000:500);  // 绱犳暟鎼滅储棰勭畻 (4096-bit 閫傚綅)
    BN p,q,n,phi,e,d;
    e=BN::from_uint64(65537);
    // 绱犳暟鎼滅储 (瓒呮椂 鈫?棰勫埗绱犳暟鍏滃簳, 闃叉鍋跺彂鍗℃瀵艰嚧 keygen 闀挎椂闂存棤鍝嶅簲)
    {
        auto dl=t0+timeout;
        if(!CAT(kgen_next_prime_,K)(p,q,dl))CAT(kgen_prebuilt_,K)(p,0);
    }
    {
        auto dl=t0+timeout;
        if(!CAT(kgen_next_prime_,K)(q,p,dl)){
            do{CAT(kgen_prebuilt_,K)(q,1);}while(q==p);
        }
    }
    bn_mul(n,p,q);
    BN p1,q1;bn_sub(p1,p,BN::from_uint64(1));bn_sub(q1,q,BN::from_uint64(1));
    bn_mul(phi,p1,q1);bn_modinv(d,e,phi);
    // n 浣嶅涓嶈冻 鈫?鐩存帴鐢ㄩ鍒剁礌鏁扮粍鍚堥噸璇?(鏈€楂樹綅鍧囧凡缃?1, 鏈熸湜 2 娆″唴婊¤冻)
    while(n.bit_length()<K*64){
        CAT(kgen_prebuilt_,K)(p,0);
        do{CAT(kgen_prebuilt_,K)(q,1);}while(q==p);
        bn_mul(n,p,q);
        bn_sub(p1,p,BN::from_uint64(1));bn_sub(q1,q,BN::from_uint64(1));
        bn_mul(phi,p1,q1);bn_modinv(d,e,phi);
    }
    pub.n=n;pub.e=e;prv.n=n;prv.d=d;prv.e=e;
    /* CRT 鍙傛暟: dP=d mod (p-1), dQ=d mod (q-1), qInv=q^{-1} mod p (渚涜В瀵嗗揩閫熻矾寰? */
    bn_mod(prv.dP,d,p1);bn_mod(prv.dQ,d,q1);
    /* qInv 用费马小定理: q^{p-2} mod p (半宽模幂 ~ms 级, 替代除法欧几里得 ~700ms) */
    {BN p2;bn_sub(p2,p,BN::from_uint64(2));MONT_CTX mcp=CAT(mont_init_mp_,K)(p);
     CAT(mont_modpow_half_win8_,K)(prv.qInv,q,p2,mcp,p);}
    prv.p=p;prv.q=q;return 1;
}

void CAT(enc_fn_,K)(const PUB_KEY&pub,jpssl::span<const uint8_t> pt,uint8_t*ct){size_t pl=pt.size(),bl=K*8;uint8_t pad[512]={};pad[0]=0;pad[1]=2;size_t pdl=bl-pl-3;if(pdl){secure_rand_bytes(pad+2,pdl);for(size_t i=0;i<pdl;++i)if(pad[2+i]==0)pad[2+i]=1;}pad[2+pdl]=0;memcpy(pad+3+pdl,pt.data(),pl);BN m=BN::from_bytes(pad,bl),c;MONT_CTX mc=CAT(mont_init_cached_,K)(pub.n);if(pub.e.bit_length()>=64)CAT(mont_modpow_win_fn_,K)(c,m,pub.e,mc,pub.n);else CAT(mont_modpow_fn_,K)(c,m,pub.e,mc,pub.n);c.to_bytes(ct);}
bool CAT(dec_fn_,K)(const PRIV_KEY&prv,const uint8_t*ct,std::vector<uint8_t>&pt){size_t bl=K*8;BN c=BN::from_bytes(ct,bl),m;if(!prv.p.is_zero()&&!prv.q.is_zero()){/* CRT fast path (half-size 8-bit window): m1=c^dP mod p, m2=c^dQ mod q, Garner combine */MONT_CTX mcp=CAT(mont_init_mp_,K)(prv.p),mcq=CAT(mont_init_mp_,K)(prv.q);BN Rh_p,R2h_p,Rh_q,R2h_q;CAT(half_rh_get_,K)(prv.p,Rh_p,R2h_p);CAT(half_rh_get_,K)(prv.q,Rh_q,R2h_q);BN m1,m2;
#ifdef _OPENMP
/* CRT two modpows fully independent -> OpenMP dual-path parallel;
   thread-safe: all state is stack-local, only read-shared, mont_mul_asm has no globals */
#pragma omp parallel sections num_threads(2)
{
#pragma omp section
{CAT(mont_modpow_half_win8_ex_,K)(m1,c,prv.dP,mcp,prv.p,Rh_p,R2h_p);}
#pragma omp section
{CAT(mont_modpow_half_win8_ex_,K)(m2,c,prv.dQ,mcq,prv.q,Rh_q,R2h_q);}
}
#else
CAT(mont_modpow_half_win8_ex_,K)(m1,c,prv.dP,mcp,prv.p,Rh_p,R2h_p);CAT(mont_modpow_half_win8_ex_,K)(m2,c,prv.dQ,mcq,prv.q,Rh_q,R2h_q);
#endif
BN m2p;if(m2<prv.p)m2p=m2;else bn_mod(m2p,m2,prv.p);BN h;if(m1<m2p){BN tmp;bn_sub(tmp,prv.p,m2p);bn_add(h,m1,tmp);}else bn_sub(h,m1,m2p);BN qInv_m;CAT(mont_mul_half_,K)(qInv_m,prv.qInv,R2h_p,prv.p,mcp.m_prime);BN h2;CAT(mont_mul_half_,K)(h2,h,qInv_m,prv.p,mcp.m_prime);BN t;bn_mul(t,prv.q,h2);bn_add(m,m2,t);if(!(m<prv.n))bn_sub(m,m,prv.n);}else{/* non-CRT privkey (d/n/e only, e.g. PEM): m = c^d mod n */bn_modpow(m,c,prv.d,prv.n);}
uint8_t pad[512];m.to_bytes(pad);if(pad[0]!=0||pad[1]!=2)return 0;size_t sep=2;while(sep<bl&&pad[sep]!=0)++sep;if(sep>=bl-1)return 0;pt.assign(pad+sep+1,pad+bl);return 1;}
