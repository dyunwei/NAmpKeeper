#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <cassert>

#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <Config.hpp>
#include <TwoBloom.hpp>

#include <bitmap.h>

TwoBloom::TwoBloom(size_t m, uint8_t k, uint8_t interval) {
   
    this->blooms[0] = new Bloom(m / 2, k);
    this->blooms[1] = new Bloom(m / 2, k);
    this->interval  = interval;
    this->bindex      = 0;
    this->current_sec = 0;
}

void 
TwoBloom::Set(const Packet *p) {
    uint64_t key[2];
    Bloom   *bloom;
    
    if (p->sec % interval == 0 
                && current_sec != p->sec) {
        current_sec = p->sec;
        bindex++;
        bloom = blooms[bindex % (sizeof(blooms) / sizeof(blooms[0]))];
        bloom->Clear();
    }
    else {
        bloom = blooms[bindex % (sizeof(blooms) / sizeof(blooms[0]))];
    }

    key[0] = p->sip;
    key[0] = (key[0] << 32) | p->dip;
    key[1] = p->sport;
    key[1] = (key[1] << 32) | p->id;
    
    bloom->Set(key, sizeof(key));
}

int 
TwoBloom::Check(const Packet *p) {
    uint64_t key[2];
    Bloom   *bloom;

    if (p->sec % interval == 0 
                && current_sec != p->sec) {
        current_sec = p->sec;
        bindex++;
        bloom = blooms[bindex % (sizeof(blooms) / sizeof(blooms[0]))];
        bloom->Clear();
    }

    // a response
    key[0] = p->dip;
    key[0] = (key[0] << 32) | p->sip;
    key[1] = p->dport;
    key[1] = (key[1] << 32) | p->id;
    
    return blooms[0]->Check(key, sizeof(key))
            || blooms[1]->Check(key, sizeof(key));
}

Bloom::Bloom(size_t mem, uint8_t k) {
    uint64_t i;

    nrows = k;
    ncols = mem / nrows;
    nbits = ncols * 8;
    
    bitmaps = new uint8_t* [nrows];
    
    for (i = 0; i < nrows; ++i) {
        bitmaps[i] = new uint8_t[ncols];
    }
}

void Bloom::Set(void *key, size_t len) {
    uint64_t n, a, b, i;

    a = MurmurHash64A(key, len, 0x9747b28c);
    b = MurmurHash64A(key, len, a);

    for (i = 0; i < nrows; ++i) {
        n = (a + b * i) % nbits;
        setbit(n, bitmaps[i]);
    }
}

int Bloom::Check(void *key, size_t len) {
    uint64_t n, a, b, i;
    uint8_t  rc = 1;

    a = MurmurHash64A(key, len, 0x9747b28c);
    b = MurmurHash64A(key, len, a);

    for (i = 0; rc && i < nrows; ++i) {
        n = (a + b * i) % nbits;
        rc = rc && getbit(n, bitmaps[i]);
    }

    return rc;
}

void Bloom::Clear(void) {
    uint64_t i;

    for (i = 0; i < nrows; ++i) {
        memset(bitmaps[i], 0, ncols);
    }
}
