#pragma once
#include <pcap.h>
#include <cstdint>
#include <cstddef>



#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t  destMac[6];
    uint8_t  srcMac[6];
    uint16_t etherType;
};


struct IPv4Header {
    uint8_t  versionIHL;       // version (high nibble) + IHL (low nibble) 
    uint8_t  tos;              // type of service
    uint16_t totalLength;
    uint16_t identification;    //fragment ID             
    uint16_t flagsFragOffset;  //  flags + fragment offset  
    uint8_t  ttl;
    uint8_t  protocol;         //  6 = TCP, 17 = UDP, 1 = ICMP  
    uint16_t checksum;
    uint32_t srcAddr;
    uint32_t destAddr;
};


    struct IPv6Header {
        uint32_t versionTrafficFlow;  //  version(4 bits) + traffic class(8) + flow label(20)
        uint16_t payloadLength;       // length of everything AFTER this header (ntohs)
        uint8_t  nextHeader;
        uint8_t  hopLimit;
        uint8_t  srcAddr[16];
        uint8_t  destAddr[16];
    };



    struct TcpHeader {
        uint16_t srcPort;
        uint16_t destPort;
        uint32_t seqNum;
        uint32_t ackNum;
        uint8_t  dataOffset;   // high nibble = header length in 32-bit words
        uint8_t  flags;        // SYN, ACK, FIN... individual bits
        uint16_t windowSize;
        uint16_t checksum;
        uint16_t urgentPtr;
    };

    struct UdpHeader {
        uint16_t srcPort;
        uint16_t destPort;
        uint16_t length;
        uint16_t checksum;
    };



    struct DnsHeader {
        uint16_t id;         // query ID (matches requests to responses)
        uint16_t flags;      // QR bit, opcode, response code, etc.
        uint16_t qdCount;    // number of questions
        uint16_t anCount;    // number of answers
        uint16_t nsCount;    // authority records
        uint16_t arCount;    // additional records
    };
#pragma pack(pop)

struct PcapDeleter {
     void operator()(pcap_t* h) const {
         if (h) { pcap_close(h); }
        }
    };

struct PcapIfDeleter {
     void operator()(pcap_if_t* allD) const {
         if (allD) { pcap_freealldevs(allD); }
       }
    };



 void printMac(const uint8_t* mac);
 void printIPv4(const uint8_t* srcAddr);
 void printIPv6(const uint8_t* addr);
 const char* dnsTypeName(uint16_t type);
 size_t readName(const u_char* data, size_t start, size_t dnsStart, bpf_u_int32 caplen);
 void readAnswer(const u_char* data, size_t dnsStart, size_t answerStart, bpf_u_int32 caplen, uint16_t anCount);
 void parseEthernet(const u_char* data, bpf_u_int32 caplen);
 void parseTransport(const u_char* data, bpf_u_int32 caplen, size_t transportOffset, uint8_t protocol);
 void parseIPv4(const u_char* data, bpf_u_int32 caplen);
 void parseIPv6(const u_char* data, bpf_u_int32 caplen);
