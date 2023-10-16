#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <cassert>

#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <DAmpADF.hpp>
#include <Mitigator.hpp>

#include <bitmap.h>

using namespace std;

Mitigator::Mitigator(size_t mk, size_t mb)
{
    bloom  = new TwoBloom(mb, K, Interval);
    cflag  = 0;

    memset(&this->stats, 0, sizeof(Stats_t));

    if (mk) {
        this->keeper = new NAmpKeeper(mk, R);
    }
    else {
        this->keeper = NULL;
    }

    this->bloom->coldStartBegin();
}

Packet_t* Mitigator::Process(Packet_t* p) {
    // https://github.com/jvirkki/libbloom/blob/master/bloom.c

    long long int   t1, t2;
    int      res, qflag;

    static double  ts;
    

#ifndef  BF
    const void  *buffer;    
    uint64_t a, b, h[R];
    FingerPrint_t F;
    int      i, res2;
#endif

    assert(p->timestamp >= ts);
    ts = p->timestamp;

    if (!Is_Valid_DNSPacket(p)) {
        // Pass
        return p;
    }

    if (Is_Valid_Response(p)) {
        // a response from A area.
        qflag  = 0;
        this->stats.n_total_responses[p->sec]++;

        if (p->isAttack) {
            this->stats.n_total_attack_responses[p->sec]++;
        }
    }
    else if (Is_Valid_Query(p)) {
        // a query from V area
        qflag  = 1;
        this->stats.n_total_queries[p->sec]++;
    }
    else {
        this->stats.n_total_others[p->sec]++;
        // Pass
        return p;
    }

    if (p->timestamp > Interval) {
        // cold start end
        this->bloom->coldStartEnd();
    }

/*
BF == bloom filters without NAmpKeeper.

make CXXFLAGS=-D=BF
*/
#ifndef BF

    t1 = get_timestamp();
    
    if (qflag) {
        buffer = &p->dip;
    }
    else {
        buffer = &p->sip;
    }
    
    a = MurmurHash64A(buffer, sizeof(uint32_t), 0x9747b28c);
    b = MurmurHash64A(buffer, sizeof(uint32_t), a);
    F = a > 0xFFFFFFFFFFFF ? a >> 48 : a;
    assert(0 != F);
    
    for (i = 0; i < R; ++i) {
        h[i] = a + b * i;
    }

    keeper->Update(qflag, h, F, p->sec);
    res2 = keeper->Check(h, F);
    
    t2 = get_timestamp();
    this->stats.total_time_of_keeper += (t2 - t1);

    if (res2) {
        if (qflag) {
            this->stats.n_identified_queries[p->sec]++;
        }
        else {
            if (p->isAttack) {
                this->stats.n_passed_attack_responses_from_keeper[p->sec]++;
                //cout << p->timestamp << "," << p->sip << "," << F << endl;
            }
        }
    
        // pass
        return p;
    }

#endif

    if (qflag) {
        t1 = get_timestamp();    
        // a query            
        bloom->Set(p);
        t2 = get_timestamp();
        this->stats.total_time_of_bl += (t2 - t1);
        
        // Pass
        return p;
    }
    else {
        // a response
        t1 = get_timestamp();
        res = bloom->Check(p);
        t2 = get_timestamp();
        this->stats.total_time_of_bl += (t2 - t1);

        if (res) {
            if (p->isAttack) {
                this->stats.n_passed_attack_responses_from_bl[p->sec]++;
            }
        
            // Pass
            return p;
        }
        else {
            // Drop
            if (!p->isAttack)
                this->stats.n_dropped_normal_responses[p->sec]++;
            return NULL;
        }
    }

}

void
Mitigator::DumpDebugData(string const &path) {
    if (this->keeper)
        this->keeper->DumpServers(path);
}

