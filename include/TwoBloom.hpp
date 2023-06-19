#ifndef    _TWOBLOOM_HPP_
#define    _TWOBLOOM_HPP_

#include <TrafficSource.hpp>


class Bloom {
    private:
        uint8_t **bitmaps;
        
    public:
        uint64_t nrows;
        uint64_t ncols;
        uint64_t nbits;
    
        Bloom(size_t mem, uint8_t k);
        void Set(void *key, size_t len);
        int Check(void *key, size_t len);
        void Clear(void);
};


class TwoBloom {
    private:
        // two blooms, used for dns query/respons one-to-one mapping.
        Bloom      *blooms[2];
        // bloom index recently used
        uint8_t    bindex;
        // Each bloom holds interval (2s) dns queries.
        uint8_t    interval;
        // current second
        uint64_t   current_sec;

    public:
        TwoBloom(size_t m, uint8_t k, uint8_t interval);
        
        void Set(const Packet *p);
        int  Check(const Packet *p);
};

#endif