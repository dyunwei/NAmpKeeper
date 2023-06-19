#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <cassert>

#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <NAmpKeeper.hpp>

using namespace std;

inline void 
increase(ExpoCounter_t *C) {
    double r;

    if (C_EXPO_MAX_VALUE == *C) {
        // reach the maximum
        // cout << "Warning: Counter reaches the maximum." << endl;
        return;
    }
    else if (*C < C_Nomal_MAX_VALUE) {
        // normal mode, add directly
        (*C)++;
        return;
    }

    // exponential mode
    r = ((double)(rand() % 10000)) / 10000;
    if (r > C_EXPO_Probability(*C)) {
        return;
    }
    else {
        // increment with a certain probability
        if (C_COEFF_PART_MASK == (*C & C_COEFF_PART_MASK)) {

            assert(C_EXPO_PART_MASK != (*C & C_EXPO_PART_MASK));

            /*
             * coefficient value reaches the maximum value
             * set coefficient part to 1 and add 1 to expo part
             */
            *C = C_Nomal_MAX_VALUE | ((*C & C_EXPO_PART_MASK) + 1);
        }
        else {
            // add 1 to coeff
            *C = *C + (1 << C_EXPO);
        }
    }
}

inline void 
decrease(ExpoCounter_t *C) {
    double r;

    if (0 == *C) {
        return;
    }

    if (*C <= C_Nomal_MAX_VALUE) {
        // normal mode
        (*C)--;
        return;
    }

    // enter exponential mode
    r = ((double)(rand() % 10000)) / 10000;

    // decrease with a certain probability
    if (r > C_EXPO_Probability(*C)) {
        return;
    }

    if (C_Nomal_MAX_VALUE == (*C & C_COEFF_PART_MASK)) {
        // exponent part minus one
        (*C)--;
        // set coeff to the max value
        *C = *C | C_COEFF_PART_MASK;
    }
    else {
        // coeff part minus 1
        *C = *C - (1 << C_EXPO);
    }
}

inline uint32_t 
get_expo(ExpoCounter_t C) {
    /*
     * return a + 2^(b+c)
     */
    return C <= C_Nomal_MAX_VALUE ? C : 
                        (C >> C_EXPO) * (1 << (C_EXPO_CURRENT_EXPOVal(C)));
}

NAmpKeeper::NAmpKeeper(size_t mem, int r) {
    int    i;
    size_t size;
    
    size = sizeof(bucket_t);
    this->r = r;
    this->w = mem / size / r;
    
    this->amplifier_threshold  = 3;
    this->hot_server_threshold = 32;

    this->buckets = new bucket_t* [this->r];
    assert(NULL != this->buckets);

    for (i = 0; i < this->r; ++i) {
        this->buckets[i] = new bucket_t[this->w];
        assert(NULL != this->buckets[i]);
    }
}

int
NAmpKeeper::Update(int qflag, uint64_t *h, uint64_t F) {
    int    u, v;
    double r, p;
    bucket_t *b;
    int amplifier = 0;

    for (u = 0; u < this->r; ++u) {
        
        v = h[u] % this->w;
        b = &buckets[u][v];

        if (qflag) {
            // process a query
            if (0 == b->QC) {
                b->F  = F;
                b->QC = 1;
            }
            else {
                if (F == b->F) {
                    increase(&b->QC);
                }
                else {
                    r = ((double)(rand() % 10000)) / 10000;
                    p = ((double)1) / pow(Decay_Probability, get_expo(b->QC));
                    
                    if (r <= p) {    
                        decrease(&b->QC);
                        decrease(&b->RC);

                        if (0 == b->QC) {
                            b->F  = F;
                            b->QC = 1;
                            b->RC = 0;
                        }
                    }
                }
            }
            
        }
        else {
            // process a response
            if (b->F == F) {
                increase(&b->RC);

                if (get_expo(b->QC) > this->hot_server_threshold 
                    && b->QC 
                    && get_expo(b->RC) > this->amplifier_threshold * get_expo(b->QC)) {

                    amplifier = 1;
                    break;
                }
            }
        }
    }


    /*
     * Clear the buckets of the amplifier to
     * make room for other servers.
     */
    if (amplifier) {
        for (u = 0; u < this->r; ++u) {
            v = h[u] % this->w;
            b = &buckets[u][v];
            
            memset(b, 0, sizeof(*b));
        }
    }

    return amplifier;
}

int
NAmpKeeper::Pass(uint64_t *h, uint64_t F) {
    int    u, v;
    bucket_t *b;

    for (u = 0; u < this->r; ++u) {
        
        v = h[u] % this->w;
        b = &buckets[u][v];

        if (b->F == F && 
                get_expo(b->QC) > this->hot_server_threshold) {
            return 1;
        }
    }

    return 0;
}

