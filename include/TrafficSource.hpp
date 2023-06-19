#ifndef    _TRAFFICSOURCE_HPP
#define    _TRAFFICSOURCE_HPP

#include <DAmpADF.hpp>

enum {
    P_TCP   = 1,
    P_UDP   = 2,
    P_DNS   = 3,
    P_IP    = 4,
    P_Other = -1
};

typedef struct Packet {
    double    timestamp;
    
    uint32_t  sip;
    uint32_t  dip;
    
    uint16_t  sport;
    uint16_t  dport;
    uint16_t  id;
    uint8_t   protocol;
    uint8_t   isA2V;
    
    uint8_t   isAttack;
    uint8_t   sec;
} Packet_t;

class TrafficSource {

    protected:
        std::list<Packet_t *> plist;
        std::list<Packet_t *> alist;

        int Load_Traffic(const std::string& background_file, 
                              const std::string& attack_file);
        void Parse_Attack(const std::string& line, Packet_t* p);
        virtual void Parse_Background(const std::string& line, Packet_t* p) = 0;
        
    public:        
        Packet_t* GetNext(void);
        bool HasTraffic(void);
        int  GetPlistSize(void) {
            return this->plist.size();
        }
        
        int  GetAListSize(void) {
            return this->alist.size();
        }
        
        void Showlist(void);
};

class TrafficWIDE: public TrafficSource {
    protected:
        void Parse_Background(const std::string& line, Packet_t* p);

    public:
        TrafficWIDE(const std::string& background_file, const std::string& attack_file);
};

class TrafficZipf: public TrafficSource {
    private:
        int    count;
        double period;

    protected:
        void Parse_Background(const std::string& line, Packet_t* p);

    public:
        TrafficZipf(const std::string& background_file, const std::string& attack_file, double period);
};

#endif
