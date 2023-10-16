#ifndef    _MITIGATOR_HPP
#define    _MITIGATOR_HPP

#include <DAmpADF.hpp>
#include <TrafficSource.hpp>
#include <TwoBloom.hpp>
#include <NAmpKeeper.hpp>

#define K        4
#define R        2

#define NSec     180
#define Attack_Start_Time 60

//#define Is_Attack_Period(p)    (p->timestamp >= Attack_Start_Time && p->timestamp < Attack_Start_Time + 60)
#define Is_Valid_DNSPacket(p)  (P_DNS == p->protocol)
#define Is_Valid_Query(p)      (53 == p->dport && 0 == p->isA2V)
#define Is_Valid_Response(p)   (53 == p->sport && 1 == p->isA2V)

typedef struct {

   int n_total_queries[NSec];
   int n_total_responses[NSec];
   int n_total_others[NSec];
   int n_total_attack_responses[NSec];

   int n_identified_queries[NSec];
   int n_dropped_normal_responses[NSec];
   int n_passed_attack_responses_from_bl[NSec];
   int n_passed_attack_responses_from_keeper[NSec];

   long long int total_time_of_keeper;
   long long int total_time_of_bl;
   
} Stats_t;

class Mitigator {
    private:
        TwoBloom      *bloom;
        NAmpKeeper    *keeper;
        bool           cflag;
    
    public:
        Stats_t stats;
    
        Mitigator(size_t dmem, size_t bmem);
        Packet_t* Process(Packet_t* p);
        void DumpDebugData(string const &path);
};

#endif