#ifndef    _DAmpADF_HPP_
#define    _DAmpADF_HPP_

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <ctime>
#include <list>

using namespace std;

#define Interval 2

uint64_t MurmurHash64A ( const void * key, int len, unsigned int seed);

static inline long long int get_timestamp()
{
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    long long milliseconds = (tv.tv_sec*1000) + (tv.tv_nsec/1000000);
    return milliseconds;
}

class Logger {
    private:
        std::ofstream  f;
    public:
        std::stringstream SS;
    
        Logger(const std::string& path) {
            this->f.open(path.c_str(), ofstream::out | ofstream::app);
            this->SS.str("");

            this->f << endl << endl;
        }

        ~Logger(void) {
            this->f.close();
        }
        
        void Write(const std::string& msg) {
            char s[32];

            time_t t = time(NULL);
            struct tm *p = localtime(&t);

            strftime(s, sizeof(s), "%x %X", p);   
            this->f << s << ": " << msg << endl;
        }

        void Flush(void) {
            this->Write(this->SS.str());
            this->SS.str("");
        }
};

#endif
