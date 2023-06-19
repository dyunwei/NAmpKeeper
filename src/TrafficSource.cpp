#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cassert>

#include <unistd.h>
#include <arpa/inet.h>

#include <DAmpADF.hpp>
#include <TrafficSource.hpp>

using namespace std;

int TrafficSource::Load_Traffic(const std::string& background_file, 
                              const std::string& attack_file) {
    string line;
    
    // load traffice into memory.
    ifstream bfile(background_file);
    ifstream afile(attack_file);

    if (afile.is_open()) {
        while (std::getline(afile, line)) {
            
            Packet_t *p = new Packet_t();            
            this->Parse_Attack(line, p);
        }
    }
    else {
        return false;
    }
    
    if (bfile.is_open()) {
        while (getline(bfile, line)) {
        
            Packet_t *p = new Packet_t();
            this->Parse_Background(line, p);
        }
    }
    else {
        return false;
    }

    return true;
}

void TrafficSource::Parse_Attack(const string& line, Packet_t* p) {
    string word;

    istringstream s(line);

    getline(s, word, ',');
    p->timestamp = stod(word) + 60;    
    p->sec = int(p->timestamp);

    p->protocol = P_DNS;
    p->isA2V = 1;
    
    getline(s, word, ',');
    p->sip = inet_addr(word.c_str());
    
    getline(s, word, ',');
    //p->sport = stoul(word);
    p->sport = 53;
    
    getline(s, word, ',');
    p->dip = inet_addr(word.c_str());
    
    getline(s, word, ',');
    p->dport = stoul(word);
    
    getline(s, word, ',');
    p->id = stoul(word);

    p->isAttack = 1;

    this->alist.push_back(p); 
}

bool TrafficSource::HasTraffic(void) {
    return !plist.empty();
}

Packet_t* TrafficSource::GetNext(void) {
    Packet_t *p1, *p2 = NULL;
    
    if (plist.empty()) {
        return NULL;
    }
    
    p1 = plist.front();

    if (!alist.empty()) {
        p2 = alist.front(); 
    }
    
    if (!p2 || p1->timestamp <= p2->timestamp) {
        plist.pop_front();
        return p1;
    }
    else {
        alist.pop_front();  
        return p2;
    }
}

void TrafficSource::Showlist(void) {
    int c = 0;

    for (auto it = plist.begin(); it != plist.end(); ++it) {
        
        if (c++ > 10) {
            break;
        }
        
        Packet_t *p = *it;
        cout << fixed << std::setprecision(6) 
            << p->timestamp << ","              \
            << unsigned(p->protocol) << ","     \
            << unsigned(p->sip) << ","          \
            << unsigned(p->sport) << ","        \
            << unsigned(p->dip) << ","          \
            << unsigned(p->dport) << ","        \
            << unsigned(p->id) << ","           \
            << unsigned(p->isA2V) << ","        \
            << unsigned(p->isAttack)            \
            << endl;
    }

    c = 0;

    cout << "\n\n" << endl;

    for (auto it = alist.begin(); it != alist.end(); ++it) {
        
        if (c++ > 10) {
            break;
        }
        
        Packet_t *p = *it;
        cout << fixed << std::setprecision(6) 
            << p->timestamp << ","              \
            << unsigned(p->protocol) << ","     \
            << unsigned(p->sip) << ","          \
            << unsigned(p->sport) << ","        \
            << unsigned(p->dip) << ","          \
            << unsigned(p->dport) << ","        \
            << unsigned(p->id) << ","           \
            << unsigned(p->isA2V) << ","        \
            << unsigned(p->isAttack)            \
            << endl;
    }
}

TrafficWIDE::TrafficWIDE(const string& background_file, 
                                const string& attack_file)
{
    int res;

    res = this->Load_Traffic(background_file, attack_file);
    assert(true == res);
}

void TrafficWIDE::Parse_Background(const string& line, Packet_t* p)
{
    string word;

    istringstream s(line);

    getline(s, word, ',');
    p->timestamp = stod(word);
    p->sec = int(p->timestamp);
    
    getline(s, word, ',');
    switch(word[0]) {
        case 't':
            p->protocol = P_TCP;
            break;
        case 'u':
            p->protocol = P_UDP;
            break;
        case 'd':
            p->protocol = P_DNS;
            break;
        case 'i':
            p->protocol = P_IP;
            break;
        default:
            p->protocol = -1;
            //cout << "invalid protocol: " << s << endl;
            break;
    }
    
    getline(s, word, ',');
    p->isA2V = stoul(word);
    
    getline(s, word, ',');
    p->sip = inet_addr(word.c_str());
    
    getline(s, word, ',');
    p->sport = stoul(word);
    
    getline(s, word, ',');
    p->dip = inet_addr(word.c_str());
    
    getline(s, word, ',');
    p->dport = stoul(word);
    
    getline(s, word, ',');
    p->id = stoul(word);

    p->isAttack = 0;

    this->plist.push_back(p);
}

TrafficZipf::TrafficZipf(const string& background_file, 
                                const string& attack_file , double period)
{
    int res;

    this->period = period;
    this->count  = 0;
    
    res = this->Load_Traffic(background_file, attack_file);
    assert(true == res);
}

void TrafficZipf::Parse_Background(const string& line, Packet_t* p)
{
    p->timestamp = this->period * this->count++;
    p->sec       = int(p->timestamp);
    p->protocol  = P_DNS;
    p->isA2V     = 0;
    p->sip       = 0;
    p->sport     = rand() % 0xFFFF;
    p->dip       = inet_addr(line.c_str());
    p->dport     = 53; 
    p->id        = rand() % 0xFFFF;
    p->isAttack  = 0;

    this->plist.push_back(p);
}

