#include "fe_448.hpp"
#include <cstdio>
#include <cstring>
using namespace jpssl::fe448_impl;

static void ph(const char* n, const uint8_t* d, size_t l) {
    printf("%s: ", n);
    for (size_t i=0;i<l;++i) printf("%02x",d[i]);
    printf("\n");
}

int main() {
    // Test: compute y^2 where y is the RFC base point y-coordinate
    uint8_t y_le[56];
    // RFC base point y, LE = 693f4671... encoded as LE
    const char* y_hex = "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f69";
    for (int i=0;i<56;++i) {
        char h[3]={y_hex[i*2],y_hex[i*2+1],0};
        y_le[i]=(uint8_t)strtol(h,nullptr,16);
    }
    fe448 y;
    fe448_frombytes(y, y_le);
    
    fe448 y_sq;
    fe448_sq(y_sq, y);
    
    uint8_t y_sq_le[56];
    fe448_tobytes(y_sq_le, y_sq);
    ph("y^2 (LE)", y_sq_le, 56);
    
    // Also compute via Python for comparison
    printf("Compare with Python...\n");
    return 0;
}
