# C++ Packet Sniffer
 
A command-line network packet analyzer written in C++ that captures live traffic
and decodes it through the full network stack — from Ethernet frames up to
DNS application-layer resolution — with a focus on safe, defensive parsing of
untrusted input.
 
Built on [Npcap](https://npcap.com/) (the Windows libpcap implementation).
 
---
 
## What it does
 
- **Live capture** on a user-selected network interface, with input validation.
- **Kernel-level BPF filtering** — filters are compiled and pushed into the OS
  kernel so unwanted packets are dropped before ever reaching the program.
- **Layered protocol parsing:**
  - Ethernet (source/destination MAC, EtherType)
  - IPv4 and IPv6 (addresses, protocol/next-header, header-length handling)
  - TCP and UDP (source/destination ports)
- **DNS application-layer decoding:**
  - Parses the question section (queried domain + record type)
  - Walks the answer section record by record
  - Follows **DNS name compression pointers** (with loop protection)
  - Resolves **CNAME chains** and prints final **A / AAAA** addresses
## Sample output
 
```
Packet captured: 213
IPv6
Source Address: 2603:7000:9ef0:92c0:0000:0000:0000:0001
Protocol: UDP
SourcePort: 53
DestPort: 60232
Query: 201367-ipv4fdsmte.gr.global.aa-rt.sharepoint.com. (A)
201367-ipv4fdsmte.gr.global.aa-rt.sharepoint.com.  CNAME -> 201367-ipv4.gr.global.aa-rt.sharepoint.com.
201367-ipv4.gr.global.aa-rt.sharepoint.com.  CNAME -> 201367-ipv4.farm.dprodmgd108.aa-rt.sharepoint.com.
201367-ipv4.farm.dprodmgd108.aa-rt.sharepoint.com.  A -> 52.104.45.27
```
 
The tool decodes a real multi-hop CNAME chain from raw packet bytes down to the
final resolved IP address.
 
## Architecture
 
The code is organized so that each function owns one layer of the network stack,
mirroring how the layers are encapsulated on the wire:
 
```
main.cpp:        capture setup, interface selection, capture loop
  parseEthernet   -> reads the Ethernet header, branches on EtherType
    parseIPv4     -> IPv4 header, computes transport offset (IHL * 4)
    parseIPv6     -> IPv6 header, fixed 40-byte layout
      parseTransport -> TCP / UDP ports (shared by both IP versions)
        (DNS)     -> readName / readAnswer decode the DNS payload
```
 
Wire-format structs (`EthernetHeader`, `IPv4Header`, `IPv6Header`,
`TcpHeader`, `UdpHeader`, `DnsHeader`) are defined in `sniffer.h` and overlaid
directly onto captured bytes. Function declarations live in `sniffer.h`;
definitions live in `sniffer.cpp`; `main.cpp` holds only `main`.
 
## Defensive parsing (security notes)
 
Packet data is **untrusted, attacker-controllable input**, and packet parsers
are a historically common source of security vulnerabilities. This project
treats every field as a claim to be verified, not a fact to be trusted:
 
- **Bounds-checking before every read.** Before overlaying any header struct or
  reading any field, the code verifies the captured length (`caplen`) actually
  contains enough bytes. Length fields inside the packet are checked against the
  real captured size, never assumed.
- **DNS name compression is followed safely.** Compression pointers let a name
  reference an earlier position in the packet. A malicious packet can craft
  pointers that reference each other in a loop — a classic denial-of-service.
  The parser caps the number of pointer jumps it will follow, so a crafted
  loop is rejected instead of hanging the program.
- **Graceful handling of the unexpected.** Unknown protocols, record types, and
  truncated packets are reported rather than silently mishandled or crashing.
## Building (Windows / Visual Studio)
 
Requires [Npcap](https://npcap.com/#download) installed (the runtime) and the
**Npcap SDK** (headers and link libraries).
 
1. Download and unzip the Npcap SDK.
2. In Visual Studio, create/open the project and set the platform to **x64**.
3. In **Project Properties** (Configuration: *All Configurations*, Platform: *x64*):
   - **C/C++ -> General -> Additional Include Directories:** add the SDK's
     `Include` folder.
   - **Linker -> General -> Additional Library Directories:** add the SDK's
     `Lib\x64` folder (the `x64` subfolder — the top-level `Lib` is 32-bit).
   - **Linker -> Input -> Additional Dependencies:** add `wpcap.lib`,
     `Packet.lib`, `ws2_32.lib`.
   - **C/C++ -> Preprocessor -> Preprocessor Definitions:** add `NOMINMAX`
     (prevents a Windows macro from clashing with `std::numeric_limits::max`).
4. Build (x64), then **run as Administrator** — live capture requires elevated
   privileges.
## Usage
 
Run the executable (as Administrator). It lists available interfaces; enter the
number of the one to capture on. The program then captures packets, applies its
BPF filter, and prints the decoded output.
 
The capture filter is currently set in source (e.g., `udp port 53` to isolate
DNS traffic). Adjust the filter string to capture other traffic.
 
## Limitations / future work
 
- IPv6 extension header chains are not walked (the common case where the next
  header is directly TCP/UDP is handled).
- DNS name compression is followed up to a fixed jump limit.
- No application-layer decoding beyond DNS (e.g., HTTP).
- Filter is compile-time rather than a command-line argument.
## What I learned
 
This was a from-scratch project to build practical experience in C++, network
protocols, and low-level binary parsing. Highlights: manual header parsing and
byte-order handling, bit manipulation (nibble masking for IPv4 version/IHL),
RAII for C-library resource management (`unique_ptr` with custom deleters for
pcap handles), and the security discipline of parsing untrusted input safely.
 
---
 
