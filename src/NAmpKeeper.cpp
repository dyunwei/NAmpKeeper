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

extern Packet_t *CP;

NAmpKeeper::NAmpKeeper(size_t mem, int r) {
    int    i;
    size_t size;

    this->maxQC = 0;
    size = sizeof(bucket_t);
    this->r = r;
    this->w = mem / size / r;
    
    this->amplifier_threshold  = Amplifier_Threshold;
    this->pop_server_threshold = Pop_Server_Threshold;

    this->buckets = new bucket_t* [this->r];
    assert(NULL != this->buckets);

    for (i = 0; i < this->r; ++i) {
        this->buckets[i] = new bucket_t[this->w];
        assert(NULL != this->buckets[i]);
    }
}

void
NAmpKeeper::Update(bool qflag, uint64_t *h, uint64_t F, int csec) {
    int    u, v;
    double r, p;
    bucket_t *b;
    bool   hasOptServer;

    for (u = 0; u < this->r; ++u) {
        
        v = h[u] % this->w;
        b = &buckets[u][v];

        if (F == b->F && b->CF && !isBucketColdStarting(b, csec)) {
            bucketColdStart_end(b, h);
        }

        hasOptServer = this->hasOptSever(h, F);

        if (qflag) {
            // process a query
            if (0 == b->QC && !hasOptServer) {
                b->F  = F;
                b->QC = 1;
                this->bucketColdStart_begin(b, csec);
            }
            else {
                if (F == b->F) {
                
                    if (b->CF) {
                        // cold start.
                        assert(b->QC < 0xFFFFFF / this->amplifier_threshold);
                        b->QC++;

                        if (CanOptimizeBuckets(b)) {
                            optimizeBuckets(b, h);
                        }
                    }
                    else {
                        // Cold Start has finished, the server should be a pop server, otherwise it should be expelled.
                        assert(isPopServer(b));
                    
                        if (isPopServer(b)) {
                            // Don't increase QC anymore.
                            if (b->QC > b->RC) {
                                b->RC = b->RC ? b->RC - 1 : 0;
                            }
                            else {
                                assert(b->RC >= b->QC);
                                b->RC -= 2;
                            }
                        }
                        else {
                            assert(b->QC < 0xFFFFFF / this->amplifier_threshold);
                            // This block of code should only be executed once.
                            b->QC++;
                            if (isPopServer(b) && isAmpServer(b)) {
                                // A valid amplifier, release buckets to make room.
#ifdef DEBUG
                                nampServers.push_back(tuple<double, uint32_t, uint16_t>(CP->timestamp, CP->dip, F));
#endif
                                this->Clear(h, F);
                                return;
                            }
                            
                            if (CanOptimizeBuckets(b)) {
                                optimizeBuckets(b, h);
                            }
                            
#ifdef DEBUG
                            if (isPopServer(b)) {
                                // a new popserver
                                popServers.push_back(tuple<double, uint32_t, uint16_t>(CP->timestamp, CP->dip, F));
                            }
#endif
                        }
                    }
                }
                else {
                    /*
                        QC  DP
                        16  0.291890468
                        32  0.085200045
                        64  0.007259048
                        128 5.26938E-05
                        256 2.77663E-09
                    */
                    if (hasOptServer || CanOptimizeBuckets(b))
                        // To save computation, since the DP is very low at this time.
                        continue;
                
                    r = ((double)(rand() % 10000)) / 10000;
                    p = ((double)1) / pow(Decay_Probability, b->QC);
                    
                    if (r <= p) {
                        b->QC -= 1;

                        if (0 == b->QC) {
                            b->F  = F;
                            b->QC = 1;
                            b->RC = 0;
                            this->bucketColdStart_begin(b, csec);
                        }
                        else {
                            b->RC = b->RC ? b->RC - 1 : 0;
                        }
                    }
                }
            }
            
        }
        else {
            // process a response
            assert(b->RC < 0xFFFFFF);
            assert(b->QC < 0xFFFFFF / this->amplifier_threshold);
            
            if (b->F == F) {
                b->RC += 1;

                if (!b->CF && isAmpServer(b)) {
                //if (!b->CF && isPopServer(b) && isAmpServer(b)) {
                    assert(isPopServer(b));
                
#ifdef DEBUG
                    ampServers.push_back(tuple<double, uint32_t, uint16_t>(CP->timestamp, CP->sip, F));
#endif

                    this->Clear(h, F);
                    return;
                }
            }
        }
    }

    return;
}

int
NAmpKeeper::Check(uint64_t *h, uint64_t F) {
    int    u, v;
    bucket_t *b;

    for (u = 0; u < this->r; ++u) {
        
        v = h[u] % this->w;
        b = &buckets[u][v];

        if (!b->CF && b->F == F && 
                isPopServer(b)) {
            return 1;
        }
    }

    return 0;
}

/*
 * Clear the buckets of the amplifier to
 * make room for other servers.
 */
void
NAmpKeeper::Clear(uint64_t *h, uint64_t F) {
    int    u, v;
    bucket_t *b;

    for (u = 0; u < this->r; ++u) {
        v = h[u] % this->w;
        b = &buckets[u][v];

        if (F == b->F) {
            memset(b, 0, sizeof(*b));
        }
    }
}

void
NAmpKeeper::optimizeBuckets(bucket_t *ob, uint64_t *h) {
    int       u, v;
    bucket_t *b;

    for (u = 0; u < this->r; ++u) {
        v = h[u] % this->w;
        b = &buckets[u][v];

        if (b == ob) {
            continue;
        }

        if (ob->F == b->F) {
            memset(b, 0, sizeof(*b));
        }
    }
}

bool
NAmpKeeper::hasOptSever(uint64_t *h, uint64_t F) {
    int    u, v;
    bucket_t *b;

    // Optimization
    for (u = 0; u < this->r; ++u) {
        v = h[u] % this->w;
        b = &buckets[u][v];

        if (F == b->F && CanOptimizeBuckets(b)) {
            return true;
        }
    }

    return false;
}

void 
NAmpKeeper::bucketColdStart_end(bucket *b, uint64_t *h) {
    b->T  = 0;
    b->CF = 0;

    if (isPopServer(b) && !isAmpServer(b)) {

        /* To avoid causing false negative by DNS responses from T0-2 */
        b->RC = b->QC * 0.5;
    
        // This bucket holds a pop server, don't need other related buckets anymore, so release them to make 
        // room.
        optimizeBuckets(b, h);

#ifdef DEBUG
        // a new popserver
        if (CP->isA2V)
            popServers.push_back(tuple<double, uint32_t, uint16_t>(CP->timestamp, CP->sip, (uint16_t)b->F));
        else
            popServers.push_back(tuple<double, uint32_t, uint16_t>(CP->timestamp, CP->dip, (uint16_t)b->F));
#endif

    }
    else {

#ifdef DEBUG
        if(isPopServer(b) && isAmpServer(b)) {
            if (CP->isA2V)
                nampServers.push_back(tuple<double, uint32_t, uint16_t>(CP->timestamp, CP->sip, (uint16_t)b->F));
            else
                nampServers.push_back(tuple<double, uint32_t, uint16_t>(CP->timestamp, CP->dip, (uint16_t)b->F));
        }
#endif

        // This bucket is an amplifier or is a server that has little queries.
        memset(b, 0, sizeof(*b));
    }
}

void 
NAmpKeeper::DumpServers(string const &path) {
    ofstream  f;

    /* Output amplifiers to the amplifier file. */
    f.open(path);
    
    /* csv header */
    f << "Type," << "Time," << "IP," << "IPINT," << "Fingerprint" << endl;
    for (auto ctuple : this->ampServers) {
        struct in_addr addr;
        addr.s_addr = get<1>(ctuple);
        
        f << "amp," << fixed << std::setprecision(6) << get<0>(ctuple) << ","     \
            << inet_ntoa(addr) << "," << addr.s_addr << ","             \
            << get<2>(ctuple) << endl;
    }

    for (auto ctuple : this->popServers) {
        struct in_addr addr;
        addr.s_addr = get<1>(ctuple);
        
        f << "pop," << fixed << std::setprecision(6) << get<0>(ctuple) << ","     \
            << inet_ntoa(addr) << "," << addr.s_addr << ","             \
            << get<2>(ctuple) << endl;
    }

    for (auto ctuple : this->npopServers) {
        struct in_addr addr;
        addr.s_addr = get<1>(ctuple);
        
        f << "npop," << fixed << std::setprecision(6) << get<0>(ctuple) << ","     \
            << inet_ntoa(addr) << "," << addr.s_addr << ","             \
            << get<2>(ctuple) << endl;
    }

    for (auto ctuple : this->nampServers) {
        struct in_addr addr;
        addr.s_addr = get<1>(ctuple);
        
        f << "namp," << fixed << std::setprecision(6) << get<0>(ctuple) << ","     \
            << inet_ntoa(addr) << "," << addr.s_addr << ","             \
            << get<2>(ctuple) << endl;
    }
    
    f.close();
}
