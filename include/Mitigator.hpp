#ifndef    _MITIGATOR_HPP
#define    _MITIGATOR_HPP

#include <DAmpADF.hpp>
#include <TrafficSource.hpp>
#include <TwoBloom.hpp>
#include <NAmpKeeper.hpp>

#define K        4
#define Interval 2
#define R        2

#define NSec     180

#define Is_Attack_Period(p)    (p->timestamp >= 60 && p->timestamp < 120)
#define Is_Valid_DNSPacket(p)  (P_DNS == p->protocol)
#define Is_Valid_Query(p)      (53 == p->dport && 0 == p->isA2V)
#define Is_Valid_Response(p)   (53 == p->sport && 1 == p->isA2V)

typedef struct {

   int n_total_queries[NSec];
   int n_total_responses[NSec];
   int n_total_others[NSec];
   int n_total_attack_responses[NSec];

   int n_identified_queries[NSec];
   int n_passed_attack_responses_from_bl[NSec];
   int n_passed_attack_responses_from_keeper[NSec];

   double total_time_of_keeper;
   double total_time_of_bl;
   
} Stats_t;

class Mitigator {
    private:
        TwoBloom      *bloom;
        NAmpKeeper    *keeper;
    
    public:
        std::list< std::tuple<double, uint32_t, uint16_t> > amplifiers;
        Stats_t stats;
    
        Mitigator(size_t dmem, size_t bmem);
        Packet_t* Process(Packet_t* p);
};

#endif