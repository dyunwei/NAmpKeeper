#include <fstream>
#include <iostream>
#include <sstream>
#include <atomic>
#include <unistd.h>
#include <arpa/inet.h>
#include <iomanip>
#include <algorithm>
#include <string>

#include <DAmpADF.hpp>
#include <TrafficSource.hpp>
#include <Mitigator.hpp>
#include <NAmpKeeper.hpp>

using namespace std;

Packet_t *CP;

/*
    log file.
*/
Logger dlog("stats/temp/log.txt");

void usage()
{
    cout    << "Usage: \n\t"
            << "bin/DAmpADF Background_Traffic_File Is_MAWI_Dataset Attack_Traffic_File "
            << " Mem_For_NAmpKeeper Mem_For_Bloomfilter AmplifierIP Label WorkingDirectory\n\n" << endl;

    cout    << "1. Background_Traffic_File: Path to the DNS background traffic file, e.g.: "
                << "dataset/mawi/2019/background_traffic.csv.\n"
            << "2. Is_MAWI_Dataset        : Enter 1 if it is a MAWI dataset. \n"
            << "3. Attack_Traffic_File    : Path to the attack traffic file, e.g.: "
                << "dataset/cic2019/attack_traffic.csv.\n" 
            << "4. Mem_For_NAmpKeeper     : Memory size in KiB for NAmpKeeper.\n"
            << "5. Mem_For_Bloomfilter    : Memory size in KiB for TwoBloomFilter.\n"
            << "6. AmplifierIP            : IP to replace the amplifier IP in the attack file, "
                << "Enter 0 if you don't want to replace it.\n"
            << "7. Label                  : Label for the result file.\n"
            << "8. WorkingDirectory       : Path to the working directory.\n"
            << endl;
}

int main(int argc, char *argv[])
{
    TrafficSource *source;

    string amplifier_file = "stats/temp/amplifier.csv";
    string output_file    = "stats/temp/";

    string background_traffic_file;    
    string attack_traffic_file;
    string workingdir, tag;

    ofstream     f;
    stringstream oss;

    int      isWIDE, i, mk, mb;
    uint32_t amplifierip = 0;

    int stats_total_qrs   = 0;
    int stats_total_res   = 0;

    if (argc == 9) {
        workingdir = argv[8];
        
        background_traffic_file = workingdir + argv[1];
        attack_traffic_file     = workingdir + argv[3];

        isWIDE = stoi(argv[2]);
        mk     = stoi(argv[4]) * 1024;
        mb     = stoi(argv[5]) * 1024;
        amplifierip = inet_network(argv[6]);        
        tag    = argv[7];
    }
    else if (argc == 2 && (string(argv[1]) == "-h")) {
        usage();
        return 0;
    }
    else {
        cout << "invlid input.\n" << endl;
    
        usage();
        return 1;
    }

#ifndef BF
    /*
        Bloom filters with NAmpKeeper.
    */

    dlog.SS << "BF+: initialize with [mk=" << mk / 1024                  \
            << "KB,mb=" << mb/1024 << "KB], label: " << tag              \
            << ",Decay_Probability=" << Decay_Probability                \
            << ",Pop_Server_Threshold PhiQ=" << Pop_Server_Threshold     \
            << ",Amplifier_Threshold PhiR=" << Amplifier_Threshold       \
            << ", amplifierip:" << amplifierip << "," << argv[6];
    dlog.Flush();

    Mitigator  mitigator(mk, mb);
#else    
    /*
        Bloom filters without NAmpKeeper.
    */

    dlog.SS << "BF : initialize with [mk=" << mk / 1024                  \
            << "KB,mb=" << mb/1024 << "KB], label: " << tag              \
            << ",Decay_Probability=" << Decay_Probability                \
            << ",Pop_Server_Threshold PhiQ=" << Pop_Server_Threshold     \
            << ",Amplifier_Threshold PhiR=" << Amplifier_Threshold       \
            << ", amplifierip:" << amplifierip << "," << argv[6];

    dlog.Flush();
    
    Mitigator  mitigator(0, mk + mb);
#endif

    dlog.SS << "Start loading " << background_traffic_file << " and " <<  attack_traffic_file;
    dlog.Flush();

    if (isWIDE) {
        /*
            Get traffic source.
        */
        source = new TrafficWIDE(background_traffic_file, attack_traffic_file);        
    }
    else {
        size_t found = background_traffic_file.find_last_of("-");

        /* 
            Get PPS from the background traffic file name. 
        */
        double    pps = std::stof(background_traffic_file.substr(found+1));
        double period = ((double)1) / (pps * 1000000);

        /*
            Get traffic source.
        */
        source = new TrafficZipf(background_traffic_file, attack_traffic_file, period);
    }

    dlog.SS << "Finish loading packets:[# of background packets: " << source->GetPlistSize()
            << ", # of attack packets: " << source->GetAListSize() << "]";
    dlog.Flush();

    //source->Showlist();
    
    dlog.Write("Start  processing.");
    
    while(source->HasTraffic()) {
        while (1) {

            /* Get next packet to process. */
            CP= source->GetNext();
            if (!CP) {
                break;
            }

            /*  Replace the amplifier IP if needed */
            if (amplifierip && CP->isAttack && CP->isA2V) {
                CP->sip = amplifierip;
            }

            /* Process the packet  */
            mitigator.Process(CP);
        }
    };

    dlog.Write("Finish processing and start outputing results.");

#ifndef BF
    oss << workingdir << output_file << (isWIDE ? "WIDE" : "Zipf")   \
        << "-" << tag << "-" << mk / 1024                            \
        << "-" << mb / 1024                                          \
        << "-ATT"  << (amplifierip ? 2 : 1) << ".csv" ;
#else
     oss << workingdir <<  output_file << (isWIDE ? "WIDE" : "Zipf") \
         << "-" << tag << "-" << mk / 1024                           \
         << "-" << mb / 1024                                         \
        << "-ATT"  << (amplifierip ? 2 : 1) << "-BF.csv" ;
#endif

    f.open(oss.str());
    
    /* csv header */
    f << "ID," << "TotalQrs," << "TotalRes," << "TotalOthers," << "IdtQrs,"       \
      << "TotalAttackRes," << "PassAttackResFromBL,"                              \
      << "PassAttackResFromKeeper" << ",DrppedNormalResponse" << endl;
    
    for (i = 0; i < NSec; ++i) {
        f << i << "," << mitigator.stats.n_total_queries[i]                            \
               << "," << mitigator.stats.n_total_responses[i]                          \
               << "," << mitigator.stats.n_total_others[i]                             \
               << "," << mitigator.stats.n_identified_queries[i]                       \
               << "," << mitigator.stats.n_total_attack_responses[i]                   \
               << "," << mitigator.stats.n_passed_attack_responses_from_bl[i]          \
               << "," << mitigator.stats.n_passed_attack_responses_from_keeper[i]      \
               << "," << mitigator.stats.n_dropped_normal_responses[i]                 \
               << endl;
    }
    
    f.close();    
    oss.str("");

    {
        int total_idenq = 0;
        int total_passb = 0;
        int total_passk = 0;
        int total_dropr = 0;
        
        for (i = 60; i < 120; ++i) {            
            total_passb += mitigator.stats.n_passed_attack_responses_from_bl[i];
            total_passk += mitigator.stats.n_passed_attack_responses_from_keeper[i];
            total_idenq += mitigator.stats.n_identified_queries[i];
            total_dropr += mitigator.stats.n_dropped_normal_responses[i];
        }

        for (i = 0; i < NSec; ++i) {
            stats_total_qrs   += mitigator.stats.n_total_queries[i];
            stats_total_res   += mitigator.stats.n_total_responses[i];
        }

        dlog.SS << "[query]    total: " << stats_total_qrs   \
                << ",  identified: " << total_idenq;
        dlog.Flush();
        
        dlog.SS << "[response] total: " << stats_total_res    \
                << ",      passb: " << total_passb      \
                << ",      passk: " << total_passk      \
                << ",      dropr: " << total_dropr;
        dlog.Flush();
    }

    dlog.SS << "[perf] NAmpkeepr: " << mitigator.stats.total_time_of_keeper << "ms"  \
            << ", TwoBloomFilter: " << mitigator.stats.total_time_of_bl << "ms"
            << ", PPS: " << ((double)(stats_total_qrs + stats_total_res)) / 
                (mitigator.stats.total_time_of_keeper + mitigator.stats.total_time_of_bl);
    dlog.Flush();


#ifndef BF
            oss << workingdir << amplifier_file         \
                << "-" << tag << "-" << mk / 1024      \
                << "-" << mb / 1024 << "-ATT"           \
                << (amplifierip ? 2 : 1) <<".csv" ; 
#else
            oss << workingdir << amplifier_file         \
                << "-" << tag << "-" << mk / 1024      \
                << "-" << mb / 1024 << "-ATT"           \
                << (amplifierip ? 2 : 1) << "-BF.csv" ;
#endif

    mitigator.DumpDebugData(oss.str());

    return 0;
}


