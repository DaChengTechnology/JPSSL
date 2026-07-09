// rsa_body.inc — RSA 大整数运算宏模板
// 使用前需定义: K, BN, PUB_KEY, PRIV_KEY, CTX, MONT_CTX
// BN = rsa_bignum / rsa4096_bignum
// K = 32 / 64

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
BN BN::from_bytes(const uint8_t*data,size_t len){BN r;r.zero();for(size_t i=0;i<len;++i)r.d[i/8]|=(uint64_t)data[len-1-i]<<((i%8)*8);return r;}
void BN::to_bytes(uint8_t*out)const{size_t bl=K*8;memset(out,0,bl);for(size_t i=0;i<bl;++i)out[bl-1-i]=(uint8_t)(d[i/8]>>((i%8)*8));}
BN BN::random_odd(){BN r;static std::mt19937_64 g(std::random_device{}());for(int i=0;i<K;++i)r.d[i]=g();r.d[K-1]|=(uint64_t)1<<63;r.d[0]|=1;return r;}

void bn_add(BN&r,const BN&a,const BN&b){uint64_t c=0;for(int i=0;i<K;++i){uint64_t s=a.d[i]+b.d[i]+c;c=(s<a.d[i])?1:0;r.d[i]=s;}}
void bn_sub(BN&r,const BN&a,const BN&b){uint64_t bo=0;for(int i=0;i<K;++i){uint64_t df=a.d[i]-b.d[i]-bo;bo=(a.d[i]<b.d[i]+bo)?1:0;r.d[i]=df;}}
void bn_mul(BN&r,const BN&a,const BN&b){BN t;for(int i=0;i<K;++i){if(!a.d[i])continue;uint64_t ca=0;for(int j=0;j<K-i;++j){__uint128_t p=(__uint128_t)a.d[i]*b.d[j]+t.d[i+j]+ca;t.d[i+j]=(uint64_t)p;ca=(uint64_t)(p>>64);}}r=t;}

void bn_divmod(BN&q,BN&r,const BN&a,const BN&b){r=a;q.zero();if(b.is_zero()||r<b)return;int sh=a.bit_length()-b.bit_length();BN bs;bn_lshift(bs,b,sh);for(int i=sh;i>=0;--i){if(!(r<bs)){bn_sub(r,r,bs);q.set_bit(i);}bn_rshift(bs,bs,1);}}
void bn_mod(BN&r,const BN&a,const BN&m){BN q;bn_divmod(q,r,a,m);}

void bn_rshift(BN&r,const BN&a,int bits){BN src=a;r.zero();int ws=bits/64,bs=bits%64;for(int i=0;i<K-ws;++i){r.d[i]=src.d[i+ws]>>bs;if(bs&&i+ws+1<K)r.d[i]|=src.d[i+ws+1]<<(64-bs);}}
void bn_lshift(BN&r,const BN&a,int bits){BN src=a;r.zero();int ws=bits/64,bs=bits%64;for(int i=K-1;i>=ws;--i){r.d[i]=src.d[i-ws]<<bs;if(bs&&i-ws>0)r.d[i]|=src.d[i-ws-1]>>(64-bs);}}

static uint64_t CAT(mont_mp_,K)(const BN&m){uint64_t m0=m.d[0],x=1;for(int i=0;i<63;++i)x=x*(2-m0*x);return(uint64_t)(-(int64_t)x);}
static void CAT(mont_mul_,K)(BN&r,const BN&a,const BN&b,const BN&m,uint64_t mp){uint64_t t[2*K+1]={};for(int i=0;i<K;++i){uint64_t ca=0;for(int j=0;j<K;++j){__uint128_t p=(__uint128_t)a.d[i]*b.d[j]+t[i+j]+ca;t[i+j]=(uint64_t)p;ca=(uint64_t)(p>>64);}t[i+K]=ca;uint64_t u=t[i]*mp;ca=0;for(int j=0;j<K;++j){__uint128_t s=(__uint128_t)u*m.d[j]+t[i+j]+ca;t[i+j]=(uint64_t)s;ca=(uint64_t)(s>>64);}for(int j=i+K;ca;++j){__uint128_t s=(__uint128_t)t[j]+ca;t[j]=(uint64_t)s;ca=(uint64_t)(s>>64);}}for(int i=0;i<K;++i)r.d[i]=t[i+K];BN mc=m;if(!(r<mc)){uint64_t bo=0;for(int i=0;i<K;++i){uint64_t df=r.d[i]-m.d[i]-bo;bo=(r.d[i]<m.d[i]+bo)?1:0;r.d[i]=df;}}}
static void CAT(to_mont_,K)(BN&r,const BN&a,const BN&m,const BN&R2,uint64_t mp){CAT(mont_mul_,K)(r,a,R2,m,mp);}
static void CAT(from_mont_,K)(BN&r,const BN&a,const BN&m,uint64_t mp){BN one=BN::from_uint64(1);CAT(mont_mul_,K)(r,a,one,m,mp);}

static MONT_CTX CAT(mont_init_,K)(const BN&m){MONT_CTX c;c.m_prime=CAT(mont_mp_,K)(m);BN two=BN::from_uint64(2);c.R_mod_m=two;BN tmp;int sq=(K==64?12:11);for(int i=0;i<sq;++i){bn_mul(tmp,c.R_mod_m,c.R_mod_m);bn_mod(c.R_mod_m,tmp,m);}bn_mul(tmp,c.R_mod_m,c.R_mod_m);bn_mod(c.R2_mod_m,tmp,m);return c;}

void bn_modpow(BN&r,const BN&base,const BN&exp,const BN&mod){if(mod.is_zero()){r.zero();return;}MONT_CTX mc=CAT(mont_init_,K)(mod);BN bm;CAT(to_mont_,K)(bm,base,mod,mc.R2_mod_m,mc.m_prime);BN rm=mc.R_mod_m;int bits=exp.bit_length();for(int i=bits-1;i>=0;--i){CAT(mont_mul_,K)(rm,rm,rm,mod,mc.m_prime);if(exp.bit(i))CAT(mont_mul_,K)(rm,rm,bm,mod,mc.m_prime);}CAT(from_mont_,K)(r,rm,mod,mc.m_prime);}

MONT_CTX CAT(mont_init_fn_,K)(const BN&m){return CAT(mont_init_,K)(m);}
void CAT(mont_modpow_fn_,K)(BN&r,const BN&base,const BN&exp,const MONT_CTX&mc,const BN&mod){if(mod.is_zero()){r.zero();return;}BN bm;CAT(to_mont_,K)(bm,base,mod,mc.R2_mod_m,mc.m_prime);BN rm=mc.R_mod_m;int bits=exp.bit_length();for(int i=bits-1;i>=0;--i){CAT(mont_mul_,K)(rm,rm,rm,mod,mc.m_prime);if(exp.bit(i))CAT(mont_mul_,K)(rm,rm,bm,mod,mc.m_prime);}CAT(from_mont_,K)(r,rm,mod,mc.m_prime);}

bool bn_is_prime(const BN&n,int rounds){if(n.is_zero()||n.is_one())return 0;if(n.d[0]%2==0)return n.d[0]==2;BN n1,d;bn_sub(n1,n,BN::from_uint64(1));d=n1;int s=0;while(d.d[0]%2==0){bn_rshift(d,d,1);++s;}for(int k=0;k<rounds;++k){BN a=BN::random_odd();bn_mod(a,a,n);if(a.is_zero())continue;BN x;bn_modpow(x,a,d,n);if(x.is_one()||x==n1)continue;bool comp=1;for(int r=0;r<s-1;++r){BN t;bn_mul(t,x,x);bn_mod(x,t,n);if(x==n1){comp=0;break;}}if(comp)return 0;}return 1;}
void bn_modinv(BN&r,const BN&a,const BN&m){BN or_=a,rc=m,os=BN::from_uint64(1),sc,q,p,t;while(!rc.is_zero()){BN rem;bn_divmod(q,rem,or_,rc);or_=rc;rc=rem;BN ns;bn_mul(p,q,sc);if(os<p){BN d;bn_sub(d,p,os);bn_mod(t,d,m);bn_sub(ns,m,t);}else bn_sub(ns,os,p);os=sc;sc=ns;}if(!(os<m))bn_mod(r,os,m);else r=os;}

bool CAT(keygen_fn_,K)(PUB_KEY&pub,PRIV_KEY&prv){BN p,q,n,phi,e,d;e=BN::from_uint64(65537);while(1){p=BN::random_odd();p.d[K-1]&=~((uint64_t)1<<63);p.d[K/2-1]|=(uint64_t)1<<63;if(bn_is_prime(p,5))break;}while(1){q=BN::random_odd();q.d[K-1]&=~((uint64_t)1<<63);q.d[K/2-1]|=(uint64_t)1<<63;if(bn_is_prime(q,5)&&!(p==q))break;}bn_mul(n,p,q);BN p1,q1;bn_sub(p1,p,BN::from_uint64(1));bn_sub(q1,q,BN::from_uint64(1));bn_mul(phi,p1,q1);bn_modinv(d,e,phi);pub.n=n;pub.e=e;prv.n=n;prv.d=d;prv.e=e;return 1;}
void CAT(enc_fn_,K)(const PUB_KEY&pub,std::span<const uint8_t> pt,uint8_t*ct){size_t pl=pt.size(),bl=K*8;uint8_t pad[512]={};pad[0]=0;pad[1]=2;size_t pdl=bl-pl-3;for(size_t i=0;i<pdl;++i)pad[2+i]=(uint8_t)(rand()%255+1);pad[2+pdl]=0;memcpy(pad+3+pdl,pt.data(),pl);BN m=BN::from_bytes(pad,bl),c;bn_modpow(c,m,pub.e,pub.n);c.to_bytes(ct);}
bool CAT(dec_fn_,K)(const PRIV_KEY&prv,const uint8_t*ct,std::vector<uint8_t>&pt){size_t bl=K*8;BN c=BN::from_bytes(ct,bl),m;bn_modpow(m,c,prv.d,prv.n);uint8_t pad[512];m.to_bytes(pad);if(pad[0]!=0||pad[1]!=2)return 0;size_t sep=2;while(sep<bl&&pad[sep]!=0)++sep;if(sep>=bl-1)return 0;pt.assign(pad+sep+1,pad+bl);return 1;}
