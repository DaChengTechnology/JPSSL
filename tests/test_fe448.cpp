#include "fe_448.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
using namespace jpssl::fe448_impl;
int main(){
    bool ok=true;
    for(int t=0;t<10;++t){uint8_t in[56];for(int k=0;k<56;++k)in[k]=(uint8_t)(rand()&0xff);in[55]&=0xff;fe448 f;fe448_frombytes(f,in);uint8_t out[56];fe448_tobytes(out,f);if(memcmp(in,out,56)!=0){ok=false;break;}}
    printf("[%s] roundtrip\n",ok?"PASS":"FAIL");
    {fe448 a;a[0]=2;for(int i=1;i<8;++i)a[i]=0;fe448 n;fe448_neg(n,a);fe448 s;fe448_add(s,a,n);uint8_t p[56];fe448_tobytes(p,s);bool z=true;for(int i=0;i<56;++i)if(p[i])z=false;printf("[%s] a+(-a)=0\n",z?"PASS":"FAIL");ok&=z;}
    {fe448 a;a[0]=2;for(int i=1;i<8;++i)a[i]=0;fe448 inv;fe448_invert(inv,a);fe448 p;fe448_mul(p,a,inv);uint8_t s[56];fe448_tobytes(s,p);uint8_t one[56]={0};one[0]=1;bool is1=(memcmp(s,one,56)==0);printf("[%s] a*a^-1=1\n",is1?"PASS":"FAIL");ok&=is1;}
    {fe448 a,b;a[0]=2;for(int i=1;i<8;++i)a[i]=0;for(int i=0;i<8;++i)b[i]=0;b[0]=3;fe448 ab,ba;fe448_mul(ab,a,b);fe448_mul(ba,b,a);uint8_t p1[56],p2[56];fe448_tobytes(p1,ab);fe448_tobytes(p2,ba);bool eq=(memcmp(p1,p2,56)==0);printf("[%s] a*b=b*a\n",eq?"PASS":"FAIL");ok&=eq;}
    printf("\n%s\n",ok?"ALL PASS":"SOME FAILED");return ok?0:1;
}
