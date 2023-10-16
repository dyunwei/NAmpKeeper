#ifndef    _NAMPKEEPER_HPP_
#define    _NAMPKEEPER_HPP_

#include <cassert>
#include <DAmpADF.hpp>
#include <TrafficSource.hpp>

#define Decay_Probability  1.08
/* Φr, represents the ratio of the DNS response counter value to the query counter value. */
#define Amplifier_Threshold 2
/* Φ𝑞 represents a predefined threshold used to determine the popularity of the current DNS server. */
#define Pop_Server_Threshold 20

typedef uint16_t  FingerPrint_t;

#define CanOptimizeBuckets(b) (isPopServer(b) || b->QC >= 256)
#define MaxT 0x7

typedef struct bucket {

    /* fingerprint */
    uint64_t F  : 16;
    uint64_t CF : 1;
    uint64_t T  : 3;
    /* dns response counter */
    uint64_t QC : 20;
    /* dns query counter */
    uint64_t RC : 24;  
} bucket_t;

class NAmpKeeper {
    private:
        /*
         * default is 32
         */
        uint32_t pop_server_threshold;

        /*
         * to record the max number of QC after the coldstart.
         */
        uint32_t maxQC;

        /*
         * default is 3
         */
        uint32_t amplifier_threshold;

        /*
         * r: number of rows. w: number of colomns.
         */
        uint16_t r, w;

        /*
         * buckets to store dns servers.
         */
        bucket_t **buckets;

        /*
         * indicates coldstart.
         */
        bool cflag;

        std::list< std::tuple<double, uint32_t, uint16_t> > popServers;
        std::list< std::tuple<double, uint32_t, uint16_t> > npopServers;
        std::list< std::tuple<double, uint32_t, uint16_t> > ampServers;
        std::list< std::tuple<double, uint32_t, uint16_t> > nampServers;
        
    private:
        bool isPopServer(bucket_t *b) {
            return b->QC >= this->pop_server_threshold;
        }

        bool isAmpServer(bucket_t *b) {
            return b->RC > this->amplifier_threshold * b->QC;
        }

        void bucketColdStart_begin(bucket *b, int csec) {
            b->T = csec % MaxT;
            b->CF = 1;
        }

        bool isBucketColdStarting(bucket *b, int csec) {
            int t = (csec % MaxT + MaxT - b->T) % MaxT;
            assert(t < MaxT);
            return t <= Interval;
        }

        /* The bucket has finished the Cold Start. */
        void bucketColdStart_end(bucket *b, uint64_t *h);

        /* Indicate if F has corresponding pop server */
        bool hasOptSever(uint64_t *h, uint64_t F);

        /* Release other bucket since the ob has been a pop server. */
        void optimizeBuckets(bucket_t *ob, uint64_t *h);

    public:
        NAmpKeeper(size_t m, int r);
        void Update(bool qflag, uint64_t *h, uint64_t F, int csec);
        int Check(uint64_t *h, uint64_t F);
        void Clear(uint64_t *h, uint64_t F);
        void DumpServers(string const &path);
};

#endif