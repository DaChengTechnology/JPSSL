/**
 * sha512_gpu.mu — MUSA GPU SHA-384/SHA-512 kernel
 *
 * Each thread processes one 128-byte block and produces the hash.
 * For multi-block messages, the host iterates.
 */

#include <musa_runtime.h>
#include <stdint.h>

#define ROR(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define S0(x) (ROR(x,28)^ROR(x,34)^ROR(x,39))
#define S1(x) (ROR(x,14)^ROR(x,18)^ROR(x,41))
#define s0(x) (ROR(x,1)^ROR(x,8)^((x)>>7))
#define s1(x) (ROR(x,19)^ROR(x,61)^((x)>>6))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))

__constant__ uint64_t d_K[80];

static __device__ inline uint64_t ld_be64(const uint8_t* p){
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)|((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|((uint64_t)p[6]<<8)|(uint64_t)p[7];
}

static __device__ void sha512_gpu_transform(uint64_t h[8], const uint8_t data[128]){
    uint64_t w[80];
    for(int i=0;i<16;++i) w[i]=ld_be64(data+i*8);
    for(int i=16;i<80;++i) w[i]=s1(w[i-2])+w[i-7]+s0(w[i-15])+w[i-16];
    uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for(int i=0;i<80;++i){
        uint64_t t1=hh+S1(e)+CH(e,f,g)+d_K[i]+w[i];
        uint64_t t2=S0(a)+MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
    h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

/**
 * SHA-512 GPU kernel
 * Each thread processes one independent message (single-block).
 * For messages > 128 bytes, chain multiple blocks per thread.
 * 
 * d_input:  array of messages, each padded to 128-byte blocks
 * d_output: array of 64-byte digests
 * num_msgs: number of independent messages
 */
extern "C" __global__ void sha512_gpu_kernel(
    const uint8_t* __restrict__ d_input,
    uint8_t* __restrict__ d_output,
    int num_msgs,
    int is_384)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_msgs) return;

    const uint8_t* in = d_input + idx * 128;
    uint8_t* out  = d_output + (is_384 ? idx * 48 : idx * 64);

    uint64_t h[8];
    if (is_384) {
        h[0]=0xcbbb9d5dc1059ed8; h[1]=0x629a292a367cd507;
        h[2]=0x9159015a3070dd17; h[3]=0x152fecd8f70e5939;
        h[4]=0x67332667ffc00b31; h[5]=0x8eb44a8768581511;
        h[6]=0xdb0c2e0d64f98fa7; h[7]=0x47b5481dbefa4fa4;
    } else {
        h[0]=0x6a09e667f3bcc908; h[1]=0xbb67ae8584caa73b;
        h[2]=0x3c6ef372fe94f82b; h[3]=0xa54ff53a5f1d36f1;
        h[4]=0x510e527fade682d1; h[5]=0x9b05688c2b3e6c1f;
        h[6]=0x1f83d9abfb41bd6b; h[7]=0x5be0cd19137e2179;
    }

    sha512_gpu_transform(h, in);

    int out_size = is_384 ? 48 : 64;
    for (int i = 0; i < out_size; ++i)
        out[i] = (uint8_t)(h[i/8] >> (56 - (i%8)*8));
}

extern "C" void musa_sha512_gpu_init() {
    const uint64_t K[80]={
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
    0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
    0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
    0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
    0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
    0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
    0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
    0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
    0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817};
    musaMemcpyToSymbol(d_K, K, sizeof(K), 0, musaMemcpyHostToDevice);
}

extern "C" void launch_sha512_gpu(
    const uint8_t* d_input, uint8_t* d_output,
    int num_msgs, int is_384,
    int threads_per_block, musaStream_t stream)
{
    int grid_size = (num_msgs + threads_per_block - 1) / threads_per_block;
    sha512_gpu_kernel<<<grid_size, threads_per_block, 0, stream>>>(
        d_input, d_output, num_msgs, is_384);
}
