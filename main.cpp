#include <pcap.h>
#include <iostream>
#include <limits>
#include <cstdint>
#include<iomanip>
#include<iterator>
#include "sniffer.h"





int main() {
    pcap_if_t* allDevs_temp{ nullptr };
    char errbuf[PCAP_ERRBUF_SIZE];
    int counter{ 0 };
    int choice{};
  
  

    if (pcap_findalldevs(&allDevs_temp, errbuf) == -1) {
        std::cerr << "Error locating device: " << errbuf << '\n';
        return 1;
    }

    std::unique_ptr<pcap_if_t, PcapIfDeleter> allDevs{ allDevs_temp };
    
    pcap_if_t* chosenDevice{ allDevs.get()};


    for (pcap_if_t* d{ allDevs.get()}; d != nullptr; d = d->next) {
        ++counter;
        std::cout << "#" << counter << " Name: " << d->name << '\n';
        if (d->description) { std::cout <<"Description: "<< d->description<<'\n'; }
        std::cout<<"-----------------------------------------" << '\n';
      
    }

    do {
        std::cout << "Which device would you like to choose: ";
        if (!(std::cin >> choice)) {
            std::cerr << "Invalid input: not a number.\n";
            std::cin.clear();
            std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
        }
       
    } while (choice <= 0 || choice > counter);
        
    

    counter = 0;
    for (pcap_if_t* d{ allDevs.get()}; d != nullptr; d = d->next) {
        ++counter;
        if (counter == choice) {
            chosenDevice = d;
            break;
      }
        
    }

  
    std::unique_ptr<pcap_t, PcapDeleter> handle{pcap_open_live(
        chosenDevice->name,
        65535,
        0,
        1000,
        errbuf
    ) };
  

    if (handle == nullptr) {
        std::cerr << "Failed to open Wi-Fi interface: " << errbuf<<'\n';
        return 1;
    }
    else {
        std::cout << "Device: " << chosenDevice->description << " was chosen." << '\n';
        std::cout << "Success"<<'\n';
        std::cout << "------------------------------------" << '\n';
    }

   
    pcap_pkthdr* header;
    const u_char* data;
    int packetsWanted{ 10 };
    int packetsGot{ 0 };
    bpf_program fp{};
    const char* filter{ "udp port 53" };
    int optimize{ 1 };

    int compile{ pcap_compile(handle.get(), &fp, filter, optimize, PCAP_NETMASK_UNKNOWN) };
    if (compile == -1) {
        std::cout << "Compile Error: " << pcap_geterr(handle.get());
        return 1;
    } 

    int setFilter{ pcap_setfilter(handle.get(), &fp) };
    if (setFilter == -1) {
        std::cout << "Error Setting Filter: " << pcap_geterr(handle.get());
        pcap_freecode(&fp);

        return 1;
    }
   


    while (packetsGot < packetsWanted) {
        int result = pcap_next_ex(handle.get(), &header, &data);

        if (result == 1) {
            if (header->caplen < sizeof(EthernetHeader)) {
                std::cout << "Packet too short" << '\n';
            }
            else {
                std::cout << "Packet captured: " << header->caplen<<'\n';
                ++packetsGot;
                parseEthernet(data, header->caplen);
               
            }
           
        }


        else if (result == 0) {
            continue;
        }


        else if (result == -1) {
            std::cout <<"Capture Error: "<< pcap_geterr(handle.get()) << '\n';
            pcap_freecode(&fp);

            break;
        }


        else {
            std::cout << "End of capture.\n";
            pcap_freecode(&fp);

            break;
        }
    }

    pcap_freecode(&fp);

    return 0;
}
