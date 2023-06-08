#ifndef    _NAMPKEEPER_HPP_
#define    _NAMPKEEPER_HPP_

#include <Config.hpp>

#define C_COEFF       5
#define C_EXPO        3

#define C_COEFF_PART_MASK     0xF8
#define C_EXPO_PART_MASK      0x07

#define C_Nomal_MAX_VALUE     0x80
#define C_EXPO_MAX_VALUE      0xFF
#define C_EXPO_DECAY_VALUE    0xFC

// = 1/8
#define C_EXPO_CURRENT_EXPOVal(C) (C_EXPO + (C & C_EXPO_PART_MASK))
#define C_EXPO_Probability(C)     (((double)1) / (1 << (C_EXPO_CURRENT_EXPOVal(C))))

#define Decay_Probability  1.08

typedef uint16_t  FingerPrint_t;
typedef uint8_t   ExpoCounter_t;

typedef struct bucket {

    /* fingerprint */
    FingerPrint_t F;
    /* dns response counter */
    ExpoCounter_t RC;
    /* dns query counter */
    ExpoCounter_t QC;    
} bucket_t;

class NAmpKeeper {
    private:
        /*
         * default is 32
         */
        uint8_t hot_server_threshold;

        /*
         * default is 3
         */
        uint8_t amplifier_threshold;

        uint16_t r, w;

        bucket_t **buckets;

    public:
        NAmpKeeper(size_t m, int r);
        int Update(int qflag, uint64_t *h, uint64_t F);
        int Pass(uint64_t *h, uint64_t F);
};

#endif