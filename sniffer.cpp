
#include <iostream>      
#include <iomanip>      
#include "sniffer.h"



void printMac(const uint8_t* mac) {

    std::cout << std::hex << std::setfill('0');
    for (size_t i{ 0 }; i < 6; ++i) {
        std::cout << std::setw(2) << static_cast<int>(mac[i]);
        if (i < 5) { std::cout << ':'; }
    }
    std::cout << std::dec << '\n';
}
void printIPv4(const uint8_t* srcAddr) {
    for (int i{ 0 }; i < 4; ++i) {
        std::cout << static_cast<int>(srcAddr[i]);
        if (i < 3) std::cout << '.';
    }
    std::cout << '\n';
}
void printIPv6(const uint8_t* addr) {
    std::cout << std::hex << std::setfill('0');
    for (size_t i{ 0 }; i < 16; i += 2) {
        uint16_t group = (addr[i] << 8) | addr[i + 1];
        std::cout << std::setw(4) << group;
        if (i < 14) std::cout << ':';
    }
    std::cout << std::dec << '\n';
}

const char* dnsTypeName(const uint16_t type) {
    switch (type) {
    case 1:  return "A";
    case 28: return "AAAA";
    case 5:  return "CNAME";
    case 15: return "MX";
    case 16: return "TXT";
    case 65: return "HTTPS";
    default: return "?";
    }
}

size_t readName(const u_char* data, size_t start, size_t dnsStart, const bpf_u_int32 caplen) {
    size_t pos{ start };
    size_t consumed{ 0 };
    bool jumped{ false };
    int jumpCount{ 0 };
    const int MAX_JUMPS{ 10 };

    while (true) {
        if (pos >= caplen) { break; }
        uint8_t len{ data[pos] };

        if (len == 0) {
            if (!jumped) { consumed += 1; }
            break;
        }
        else if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= caplen) { break; }
            if (!jumped) { consumed += 2; }
            int offSet{ ((len & 0x3F) << 8 | data[pos + 1]) };
            if (jumpCount >= MAX_JUMPS) { break; }
            jumpCount++;
            pos = dnsStart + offSet;
            jumped = true;
        }
        else {
            if (pos + len + 1 > caplen) { break; }

            for (size_t i{ 1 }; i <= len; ++i) {
                std::cout << static_cast<char>(data[pos + i]);
            }
            pos += len + 1;
            if (!jumped) { consumed += len + 1; }
            std::cout << ".";
        }
    }

    return consumed;
}

void readAnswer(const u_char* data, size_t dnsStart, size_t answerStart, const bpf_u_int32 caplen, const uint16_t anCount) {
    size_t answerPos{ answerStart };
    size_t anCount_m{ ntohs(anCount) };

    for (size_t i{ 0 }; i < anCount_m; i++) {
        size_t consumed{ readName(data, answerPos, dnsStart,caplen) };
        answerPos += consumed;
        if (answerPos + 10 > caplen) { break; }

        const uint16_t type{ ntohs(*reinterpret_cast<const uint16_t*>(&data[answerPos])) };
        const uint16_t rdlength{ ntohs(*reinterpret_cast<const uint16_t*>(&data[answerPos + 8])) };

        if (answerPos + 10 + rdlength > caplen) { break; }

        std::cout << "  " << dnsTypeName(type) << " -> ";

        if (type == 1 && rdlength == 4) {
            printIPv4(&data[answerPos + 10]);

        }
        else if (type == 28 && rdlength == 16) {
            printIPv6(&data[answerPos + 10]);
        }
        else if (type == 5) {
            readName(data, answerPos + 10, dnsStart, caplen);
            std::cout << '\n';
        }
        else {
            std::cout << "(" << rdlength << " bytes)" << '\n';
        }


        answerPos += 10 + rdlength;

    }
}
void parseEthernet(const u_char* data, bpf_u_int32 caplen){
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(data);
    uint16_t type = ntohs(eth->etherType);
    if (type == 0x0800) {
        std::cout << "IPv4" << '\n';
        parseIPv4(data, caplen);
    }
    else if (type == 0x86DD) {
        std::cout << "IPv6" << '\n';
        parseIPv6(data, caplen);
        std::cout << "------------------------------------" << '\n';
    }
    else if (type == 0x0806) {
        std::cout << "ARP ";
        printMac(eth->srcMac);
        std::cout << "------------------------------------" << '\n';
    }
    else {
        std::cout << "Other: 0x" << std::hex << type << " " << std::dec;
        std::cout << "------------------------------------" << '\n';
    }
}
void parseTransport(const u_char* data, const bpf_u_int32 caplen, size_t transportOffset, uint8_t protocol) {
    switch (static_cast<int>(protocol)) {
    case 6:
        std::cout << "Protocol:TCP " << '\n';
        if (caplen >= transportOffset + sizeof(TcpHeader)) {
            const TcpHeader* tcp = reinterpret_cast<const TcpHeader*>(data + transportOffset);
            std::cout << "SourcePort: " << ntohs(tcp->srcPort) << '\n';
            std::cout << "DestPort: " << ntohs(tcp->destPort) << '\n';
        }
        else {
            std::cout << "  (Cut Off: not enough bytes for tcp header) " << '\n';
        }

        break;

    case 17:
        std::cout << "Protocol: UDP" << '\n';
        if (caplen >= transportOffset + sizeof(UdpHeader)) {
            const UdpHeader* udp = reinterpret_cast<const UdpHeader*>(data + transportOffset);
            std::cout << "SourcePort: " << ntohs(udp->srcPort) << '\n';
            std::cout << "DestPort: " << ntohs(udp->destPort) << '\n';

            if (caplen >= transportOffset + sizeof(UdpHeader) + sizeof(DnsHeader)) {
                size_t dnsStart{ transportOffset + sizeof(UdpHeader) };
                const DnsHeader* dns{ reinterpret_cast<const DnsHeader*>(data + transportOffset + sizeof(UdpHeader)) };

                size_t questionStart = transportOffset + sizeof(UdpHeader) + sizeof(DnsHeader);

                std::cout << "Query: ";
                size_t consumed = readName(data, questionStart, dnsStart, caplen);


                if (caplen >= questionStart + consumed + 2) {
                    const uint16_t qtype{ ntohs(*reinterpret_cast<const uint16_t*>(&data[questionStart + consumed])) };
                    std::cout << " (" << dnsTypeName(qtype) << ")\n";
                }


                size_t answerStart{ questionStart + consumed + 4 };
                readAnswer(data, dnsStart, answerStart, caplen, dns->anCount);

            }
        }
        else {
            std::cout << "  (Cut Off: not enough bytes for udp header) " << '\n';
        }
        break;

    default:
        std::cout << "Protocol: " << static_cast<int>(protocol) << '\n';
        break;
    }
    std::cout << "------------------------------------" << '\n';

}

void parseIPv4(const u_char* data, const bpf_u_int32 caplen) {
    if (caplen >= sizeof(EthernetHeader) + sizeof(IPv4Header)) {
        const IPv4Header* IPv4 = reinterpret_cast<const IPv4Header*>(data + sizeof(EthernetHeader));
        uint8_t IHL = IPv4->versionIHL & 0x0F;
        uint8_t Version = IPv4->versionIHL >> 4;
        size_t transportOffset = sizeof(EthernetHeader) + (IHL * 4);
        std::cout << "Source Address: ";
        printIPv4(reinterpret_cast<const uint8_t*>(&IPv4->srcAddr));
        std::cout << "IHL: " << IHL * 4 << " bytes" << '\n';

        if (static_cast<int>(IPv4->protocol) == 1) {
            std::cout << "Protocol: ICMP" << '\n';
        }
        else { parseTransport(data, caplen, transportOffset, IPv4->protocol); }

    }
}

void parseIPv6(const u_char* data, const bpf_u_int32 caplen) {
    if (caplen >= sizeof(EthernetHeader) + sizeof(IPv6Header)) {
        const IPv6Header* IPv6 = reinterpret_cast<const IPv6Header*>(data + sizeof(EthernetHeader));
        uint8_t Version = ntohl(IPv6->versionTrafficFlow) >> 28;
        size_t transportOffset = sizeof(EthernetHeader) + sizeof(IPv6Header);
        std::cout << "Source Address: ";
        printIPv6(IPv6->srcAddr);

        if (static_cast<int>(IPv6->nextHeader) == 58) {
            std::cout << "Protocol: ICMPv6" << '\n';
        }
        else { parseTransport(data, caplen, transportOffset, IPv6->nextHeader); }

    }

}
