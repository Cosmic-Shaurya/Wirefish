#include <cstdint>
#include <cstddef>
#include <memory>
#include <pcap.h>

#include <iostream>
#include <chrono>
#include <vector>

#include <array>
#include <optional>
#include <unordered_map>
#include <string>
#include <cstring>

using namespace std;

// ==================== Byte utilities ====================

// take two bytes and return a 16-bit number (big endian)
inline uint16_t read_u16_be(const uint8_t* p) { 
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

// take four bytes and return a 32-bit number (big endian)
inline uint32_t read_u32_be(const uint8_t* p) { 
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

// four bytes -> 32 bit number but in host-byte order
inline uint32_t read_u32_host(const uint8_t* p) { 
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

// ==================== L2 structures ====================

using MacAddr = array<uint8_t, 6>;

// values that appear in ether type field
enum class EtherProto : uint16_t {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    VLAN = 0x8100,
    Unknown = 0xFFFF
};

// convert 16-bit number to EtherProto
static EtherProto to_ether_proto(uint16_t v) {
    switch (v) {
        case 0x0800: return EtherProto::IPv4;
        case 0x0806: return EtherProto::ARP;
        case 0x86DD: return EtherProto::IPv6;
        case 0x8100: return EtherProto::VLAN;
        default:     return EtherProto::Unknown;
    }
}

struct L2Info {
    optional<MacAddr> src_mac;
    optional<MacAddr> dst_mac;
    EtherProto proto;
    size_t header_len;
};

// base class for different data link layer protocols
struct L2Parser { 
    virtual optional<L2Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L2Parser() = default;

protected:
    static MacAddr read_mac(const uint8_t* p) { // take six bytes and return a MAC address
        return {p[0], p[1], p[2], p[3], p[4], p[5]};
    }
};

// note that things like preamble, sfd and fcs are stripped off by the packet capturer

// format for Ethernet: [dst:6][src:6][etype:2][data]
struct EthernetParser : L2Parser {
    optional<L2Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 14) return nullopt;

        L2Info info;
        info.dst_mac = read_mac(pkt);
        info.src_mac = read_mac(pkt + 6);

        uint16_t etype = read_u16_be(pkt + 12);
        if (etype == static_cast<uint16_t>(EtherProto::VLAN)) {
            if (len < 18) return nullopt;
            etype = read_u16_be(pkt + 16); // format for VLAN is a bit different: [dst:6][src:6][0x8100:2][tag:4][etype:2][data]
            info.header_len = 18;
        }
        else {
            info.header_len = 14;
        }

        /* 
        IEEE 802.3 Ethernet standard:
        if type value is large ( >= 0x0600) then it is an Ethernet II frame. etype represents EtherType (IPv4, ARP, etc.)
        otherwise, it is an IEEE 802.3 frame. etype represents the length of the payload.
        */

        info.proto = (etype >= 0x0600) ? to_ether_proto(etype) : EtherProto::Unknown;
        
        return info;
    }
};

// this is only for Linux
// format for LinuxCooked: [pkt_type:2][arp_hw_type:2][addr_len:2][addr:8][proto:2]
struct LinuxCookedParser : L2Parser {
    optional<L2Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 16) return nullopt;

        L2Info info;
        info.header_len = 16;

        uint16_t addr_len = read_u16_be(pkt + 4);
        if (addr_len == 6)
            info.src_mac = read_mac(pkt + 6);

        info.proto = to_ether_proto(read_u16_be(pkt + 14));
        return info;
    }
};

// format for loopback: [af_family:4]
struct LoopbackParser : L2Parser {
    optional<L2Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 4) return nullopt;

        L2Info info;
        info.header_len = 4;

        uint32_t family = read_u32_host(pkt);
        if (family == 2) info.proto = EtherProto::IPv4;
        else if (family == 10 || family == 24 || family == 28 || family == 30) info.proto = EtherProto::IPv6;
        else info.proto = EtherProto::Unknown;

        return info;
    }
};

// no L2 header at all
struct RawIPParser : L2Parser {
    optional<L2Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 1) return nullopt;

        L2Info info;
        info.header_len = 0;

        uint8_t ver = pkt[0] >> 4;
        if (ver == 4)
            info.proto = EtherProto::IPv4;
        else if (ver == 6)
            info.proto = EtherProto::IPv6;
        else
            info.proto = EtherProto::Unknown;

        return info;
    }
};

class L2ParserRegistry {
    unordered_map<int, unique_ptr<L2Parser>> parsers;

public:
    L2ParserRegistry() {
        parsers[DLT_EN10MB] = make_unique<EthernetParser>();
        parsers[DLT_LINUX_SLL] = make_unique<LinuxCookedParser>();
        parsers[DLT_NULL] = make_unique<LoopbackParser>();
        parsers[DLT_RAW] = make_unique<RawIPParser>();
    }

    optional<L2Info> parse(int dlt, const uint8_t* pkt, size_t len) const {
        auto it = parsers.find(dlt);
        if (it == parsers.end()) return nullopt;
        return it->second->parse(pkt, len);
    }
};

// ==================== L3 structures ====================

using IPv4Addr = array<uint8_t, 4>;
using IPv6Addr = array<uint8_t, 16>;

// IP protocol numbers (the [protocol] field in IPv4, [next header] for IPv6)
enum class IPProto : uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
    Unknown = 0xFF
};

// convert protocol number to IPProto
static IPProto to_ip_proto(uint8_t v) {
    switch (v) {
        case 1:  return IPProto::ICMP;
        case 6:  return IPProto::TCP;
        case 17: return IPProto::UDP;
        case 58: return IPProto::ICMPv6;
        default: return IPProto::Unknown;
    }
}

// holds either an IPv4 or IPv6 address
struct IPAddr {
    bool is_v6 = false;
    IPv4Addr v4 {};
    IPv6Addr v6 {};

    static IPAddr from_v4(const uint8_t* p) {
        IPAddr a; a.is_v6 = false;
        memcpy(a.v4.data(), p, 4);
        return a;
    }

    static IPAddr from_v6(const uint8_t* p) {
        IPAddr a; a.is_v6 = true;
        memcpy(a.v6.data(), p, 16);
        return a;
    }
};

struct L3Info {
    optional<IPAddr> src_ip;
    optional<IPAddr> dst_ip;
    IPProto proto;
    uint8_t ttl; // called hop limit for ipv6
    uint16_t total_len; // datagram length in bytes
    size_t header_len;
};

// base class for network-layer parsers
struct L3Parser {
    virtual optional<L3Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L3Parser() = default;
};

/*
IPv4 header:
[ver+hdr_len:1][service_type:1][total_len:2][id:2][flags+frag:2] (flags -> 3 bits, frag -> 13 bits)
[ttl:1][protocol:1][checksum:2][src:4][dst:4]
[header options: variable number of 32 bit words]
[data]
*/
struct IPv4L3Parser : L3Parser {
    optional<L3Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 20) return nullopt;

        uint8_t hdr_len = (pkt[0] & 0x0F); // lower nibble of first byte
        size_t hdr = static_cast<size_t>(hdr_len) * 4;
        if (hdr < 20 || len < hdr) return nullopt;

        L3Info info;
        info.header_len = hdr;
        info.total_len = read_u16_be(pkt + 2); 
        info.ttl = pkt[8];
        info.proto = to_ip_proto(pkt[9]);
        info.src_ip = IPAddr::from_v4(pkt + 12);
        info.dst_ip = IPAddr::from_v4(pkt + 16);
        return info;
    }
};

/*
IPv6 header:
[ver+tc+flow:4][payload_len:2][next_header:1][hop_limit:1][src:16][dst:16]
*/
struct IPv6L3Parser : L3Parser {

    optional<L3Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 40) return nullopt;

        L3Info info;

        uint8_t next = pkt[6]; // next header
        size_t offset = 40; // how much to jump to reach actual L4 header

        while (true) {
            // check if it's an extension header
            bool is_ext = (
                next == 0  || // Hop-by-Hop
                next == 43 || // Routing
                next == 44 || // Fragment
                next == 51 || // AH
                next == 60    // Destination Options
            );

            if (!is_ext) break; // then it must be L4 header

            if (offset + 2 > len) return nullopt;

            uint8_t hdr_next = pkt[offset];
            size_t ext_size = 0;

            if (next == 44) { // Fragment
                ext_size = 8;
            } 
            else if (next == 51) { // AH
                uint8_t payload_len = pkt[offset + 1];
                ext_size = (payload_len + 2) * 4;
            } 
            else {
                uint8_t hdr_len = pkt[offset + 1];
                ext_size = (hdr_len + 1) * 8;
            }

            if (offset + ext_size > len) return nullopt;

            offset += ext_size;
            next = hdr_next;
        }

        if (next == 50) { // Encapsulating Security Payload
            info.proto = IPProto::Unknown;
        }
        else {
            info.proto = to_ip_proto(next);
        }

        info.header_len = offset;
        info.total_len = 40 + read_u16_be(pkt + 4);
        info.ttl = pkt[7];
        info.src_ip = IPAddr::from_v6(pkt + 8);
        info.dst_ip = IPAddr::from_v6(pkt + 24);

        return info;
    }
};

class L3ParserRegistry {
    unordered_map<uint16_t, unique_ptr<L3Parser>> parsers;

public:
    L3ParserRegistry() {
        parsers[static_cast<uint16_t>(EtherProto::IPv4)] = make_unique<IPv4L3Parser>();
        parsers[static_cast<uint16_t>(EtherProto::IPv6)] = make_unique<IPv6L3Parser>();
    }

    optional<L3Info> parse(EtherProto proto, const uint8_t* pkt, size_t len) const {
        auto it = parsers.find(static_cast<uint16_t>(proto));
        if (it == parsers.end()) return nullopt;
        return it->second->parse(pkt, len);
    }
};

// ==================== L4 structures ====================

// base class - holds the protocol tag
struct L4Info {
    IPProto protocol;
    size_t header_len = 0;

    explicit L4Info(IPProto p) : protocol(p) {}
    virtual ~L4Info() = default;
};

/*
TCP header:
[src_port:2][dst_port:2][seq:4][ack:4]
[data_offset+reserved+flags:2][window:2][checksum:2][urgent:2]
[options: variable]
*/
struct TcpL4Info : L4Info {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint8_t flags; // CWR ECE URG ACK PSH RST SYN FIN (high to low bit)

    // flag accessors
    bool fin()   const { return flags & 0x01; }
    bool syn()   const { return flags & 0x02; }
    bool rst()   const { return flags & 0x04; }
    bool psh()   const { return flags & 0x08; }
    bool ack_f() const { return flags & 0x10; }
    bool urg()   const { return flags & 0x20; }

    TcpL4Info() : L4Info(IPProto::TCP) {}
};

/*
UDP header:
[src_port:2][dst_port:2][length:2][checksum:2]
*/
struct UdpL4Info : L4Info {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length; // includes header + data

    UdpL4Info() : L4Info(IPProto::UDP) {}
};

/*
ICMP header (v4):
[type:1][code:1][checksum:2][rest_of_header:4]
rest_of_header interpretation depends on type/code (e.g. id+seq for echo, unused for dest unreachable)
*/
struct IcmpL4Info : L4Info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;

    IcmpL4Info() : L4Info(IPProto::ICMP) {}
};

/*
ICMPv6 header - same wire layout as ICMPv4
[type:1][code:1][checksum:2][rest_of_header:4]
*/
struct ICMPv6L4Info : L4Info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;

    ICMPv6L4Info() : L4Info(IPProto::ICMPv6) {}
};

// base class for L4 parsers - returns owning pointer to polymorphic L4Info
struct L4Parser {
    virtual unique_ptr<L4Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L4Parser() = default;
};

struct TcpL4Parser : L4Parser {
    unique_ptr<L4Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 20) return nullptr;

        uint8_t data_offset = (pkt[12] >> 4); // upper nibble of byte 12
        size_t hdr = static_cast<size_t>(data_offset) * 4;
        if (hdr < 20 || len < hdr) return nullptr;

        auto info = make_unique<TcpL4Info>();
        info->header_len = hdr;
        info->src_port = read_u16_be(pkt + 0);
        info->dst_port = read_u16_be(pkt + 2);
        info->seq = read_u32_be(pkt + 4);
        info->ack = read_u32_be(pkt + 8);
        info->flags = pkt[13];
        info->window = read_u16_be(pkt + 14);
        return info;
    }
};

struct UdpL4Parser : L4Parser {
    unique_ptr<L4Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 8) return nullptr;

        auto info = make_unique<UdpL4Info>();
        info->header_len = 8;
        info->src_port = read_u16_be(pkt + 0);
        info->dst_port = read_u16_be(pkt + 2);
        info->length = read_u16_be(pkt + 4);
        return info;
    }
};

struct IcmpL4Parser : L4Parser {
    unique_ptr<L4Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 8) return nullptr;

        auto info = make_unique<IcmpL4Info>();
        info->header_len = 8;
        info->type = pkt[0];
        info->code = pkt[1];
        info->checksum = read_u16_be(pkt + 2);
        info->rest = read_u32_be(pkt + 4);
        return info;
    }
};

struct ICMPv6L4Parser : L4Parser {
    unique_ptr<L4Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 8) return nullptr;

        auto info = make_unique<ICMPv6L4Info>();
        info->header_len = 8;
        info->type = pkt[0];
        info->code = pkt[1];
        info->checksum = read_u16_be(pkt + 2);
        info->rest = read_u32_be(pkt + 4);
        return info;
    }
};

class L4ParserRegistry {
    unordered_map<uint8_t, unique_ptr<L4Parser>> parsers;

public:
    L4ParserRegistry() {
        parsers[static_cast<uint8_t>(IPProto::TCP)] = make_unique<TcpL4Parser>();
        parsers[static_cast<uint8_t>(IPProto::UDP)] = make_unique<UdpL4Parser>();
        parsers[static_cast<uint8_t>(IPProto::ICMP)] = make_unique<IcmpL4Parser>();
        parsers[static_cast<uint8_t>(IPProto::ICMPv6)] = make_unique<ICMPv6L4Parser>();
    }

    unique_ptr<L4Info> parse(IPProto proto, const uint8_t* pkt, size_t len) const {
        auto it = parsers.find(static_cast<uint8_t>(proto));
        if (it == parsers.end()) return nullptr;
        return it->second->parse(pkt, len);
    }
};

// ==================== L5 structures ====================

// L5 protocol is inferred from well-known port numbers in the L4 header,
// since there is no explicit protocol field above L4.
enum class L5Proto : uint8_t {
    HTTP = 1,
    TLS = 2, // covers HTTPS and any other TLS-wrapped protocol
    DNS = 3,
    Unknown = 0xFF
};

// base class - holds the protocol tag
struct L5Info {
    L5Proto protocol;
    size_t header_len = 0;

    explicit L5Info(L5Proto p) : protocol(p) {}
    virtual ~L5Info() = default;
};

/*
HTTP/1.x — text framed protocol, no fixed binary header.
We capture the method/status line and whether this looks like a request or response.

Request first line:  METHOD SP request-target SP HTTP/version CRLF
Response first line: HTTP/version SP status-code SP reason CRLF
*/
enum class HttpKind : uint8_t { Request, Response };

struct HttpL5Info : L5Info {
    HttpKind kind;
    string method;      // e.g. GET, POST — only for requests
    string target;      // request-target (URI) — only for requests
    uint16_t status_code; // e.g. 200, 404 — only for responses
    string version;     // e.g. HTTP/1.1

    HttpL5Info() : L5Info(L5Proto::HTTP) {}
};

/*
TLS record header:
[content_type:1][version_major:1][version_minor:1][length:2]

content_type values:
  20 = ChangeCipherSpec
  21 = Alert
  22 = Handshake
  23 = ApplicationData

version field encodes the legacy record-layer version (not the negotiated TLS version).
  0x0301 = TLS 1.0
  0x0302 = TLS 1.1
  0x0303 = TLS 1.2 / TLS 1.3 (TLS 1.3 reuses 0x0303 in the record layer)
*/
enum class TlsContentType : uint8_t {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Unknown = 0xFF
};

static TlsContentType to_tls_content_type(uint8_t v) {
    switch (v) {
        case 20: return TlsContentType::ChangeCipherSpec;
        case 21: return TlsContentType::Alert;
        case 22: return TlsContentType::Handshake;
        case 23: return TlsContentType::ApplicationData;
        default: return TlsContentType::Unknown;
    }
}

struct TlsL5Info : L5Info {
    TlsContentType content_type;
    uint8_t version_major;
    uint8_t version_minor;
    uint16_t record_len; // length of the TLS record payload (bytes after the 5-byte header)

    TlsL5Info() : L5Info(L5Proto::TLS) {}
};

/*
DNS header:
[id:2][flags:2][qdcount:2][ancount:2][nscount:2][arcount:2]

flags breakdown (high to low):
  QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
*/
struct DnsL5Info : L5Info {
    uint16_t id;
    bool is_response;         // QR bit
    bool is_truncated;        // TC bit
    bool recursion_desired;   // RD bit
    bool recursion_available; // RA bit
    uint8_t opcode;  // 4-bit opcode
    uint8_t rcode;   // 4-bit response code
    uint16_t qdcount; // number of questions
    uint16_t ancount; // number of answers
    uint16_t nscount; // number of authority records
    uint16_t arcount; // number of additional records

    DnsL5Info() : L5Info(L5Proto::DNS) {}
};

// base class for L5 parsers
struct L5Parser {
    virtual unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L5Parser() = default;
};

struct HttpL5Parser : L5Parser {
    unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 8) return nullptr;

        // scan for the end of the first line (CRLF or just LF)
        size_t line_end = len;
        for (size_t i = 0; i + 1 < len; i++) {
            if (pkt[i] == '\r' && pkt[i + 1] == '\n') { line_end = i; break; }
            if (pkt[i] == '\n')                        { line_end = i; break; }
        }

        string first_line(reinterpret_cast<const char*>(pkt), line_end);

        auto info = make_unique<HttpL5Info>();

        // responses start with HTTP/
        if (first_line.substr(0, 5) == "HTTP/") {
            info->kind = HttpKind::Response;
            // HTTP/x.y SP status SP reason
            size_t sp1 = first_line.find(' ');
            if (sp1 == string::npos) return nullptr;

            info->version = first_line.substr(0, sp1);

            size_t sp2 = first_line.find(' ', sp1 + 1);
            string code_str = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
            info->status_code = static_cast<uint16_t>(stoi(code_str));
        }
        else {
            info->kind = HttpKind::Request;
            // METHOD SP target SP HTTP/x.y
            size_t sp1 = first_line.find(' ');
            if (sp1 == string::npos) return nullptr;

            info->method = first_line.substr(0, sp1);

            size_t sp2 = first_line.find(' ', sp1 + 1);
            if (sp2 == string::npos) return nullptr;

            info->target = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
            info->version = first_line.substr(sp2 + 1);
        }

        // header_len covers only the first line + line terminator
        info->header_len = line_end + (line_end < len && pkt[line_end] == '\r' ? 2 : 1);
        return info;
    }
};

struct TlsL5Parser : L5Parser {
    unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const override {
        // TLS record header is exactly 5 bytes
        if (len < 5) return nullptr;

        // sanity check: version major must be 3 (all SSL3/TLS versions use 3)
        if (pkt[1] != 3) return nullptr;

        TlsContentType ct = to_tls_content_type(pkt[0]);
        if (ct == TlsContentType::Unknown) return nullptr;

        auto info = make_unique<TlsL5Info>();
        info->header_len = 5;
        info->content_type = ct;
        info->version_major = pkt[1];
        info->version_minor = pkt[2];
        info->record_len = read_u16_be(pkt + 3);
        return info;
    }
};

struct DnsL5Parser : L5Parser {
    unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const override {
        // DNS header is exactly 12 bytes
        if (len < 12) return nullptr;

        auto info = make_unique<DnsL5Info>();
        info->header_len = 12;

        info->id = read_u16_be(pkt + 0);

        uint16_t flags = read_u16_be(pkt + 2);
        info->is_response = (flags >> 15) & 1;
        info->opcode = (flags >> 11) & 0x0F;
        info->is_truncated = (flags >> 9)  & 1;
        info->recursion_desired = (flags >> 8)  & 1;
        info->recursion_available = (flags >> 7)  & 1;
        info->rcode = flags & 0x0F;

        info->qdcount = read_u16_be(pkt + 4);
        info->ancount = read_u16_be(pkt + 6);
        info->nscount = read_u16_be(pkt + 8);
        info->arcount = read_u16_be(pkt + 10);
        return info;
    }
};

// L5 registry keys on port number rather than a protocol enum,
// since there is no explicit L5 protocol field on the wire.
// We check both dst_port and src_port so replies are also matched.
class L5ParserRegistry {
    unordered_map<uint16_t, unique_ptr<L5Parser>> parsers;

public:
    L5ParserRegistry() {
        parsers[80] = make_unique<HttpL5Parser>();
        parsers[8080] = make_unique<HttpL5Parser>();
        parsers[443] = make_unique<TlsL5Parser>();
        parsers[8443] = make_unique<TlsL5Parser>();
        parsers[53] = make_unique<DnsL5Parser>();
    }

    unique_ptr<L5Info> parse(uint16_t src_port, uint16_t dst_port, const uint8_t* pkt, size_t len) const {
        for (uint16_t port : {dst_port, src_port}) {
            auto it = parsers.find(port);
            if (it != parsers.end()) {
                auto result = it->second->parse(pkt, len);
                if (result) return result;
            }
        }
        return nullptr;
    }
};

// ==================== Packet Capture ====================

class PacketSource {
    pcap_t* handle;

public:
    PacketSource() {
        char errbuf[PCAP_ERRBUF_SIZE];

        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            handle = nullptr;
            return;
        }

        cout << "Device options: " << endl;
        int option_id = 1;

        for (pcap_if_t* d = alldevs; d; d = d->next) {
            cout << option_id << ". ";
            if (d->description)
                cout << "DESC: " << d->description;
            else
                cout << d->name;
            cout << endl;
            option_id++;
        }

        int user_option = 0;
        while (user_option < 1 || user_option >= option_id) {
            cout << "Pick an option: ";
            cin >> user_option;
        }

        pcap_if_t* dev = alldevs;
        for (int i = 0; i < user_option - 1; i++)
            dev = dev->next;

        handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf);

        if (!handle)
            cout << "Failed to open device\n";

        pcap_freealldevs(alldevs);
    }

    bool getPacket(const uint8_t*& packet_ptr, size_t& packet_size) {
        if (!handle) return false;

        struct pcap_pkthdr* header;
        int res = pcap_next_ex(handle, &header, &packet_ptr);
        if (res != 1) return false;

        packet_size = header->len;
        return true;
    }

    int getLinkType() const {
        return handle ? pcap_datalink(handle) : -1;
    }

    ~PacketSource() {
        if (handle) pcap_close(handle);
    }
};

class Packet {
public:
    vector<uint8_t> data;
    double time;
    int packet_id;
    optional<L2Info>   l2; // populated after stripL2(), empty until then
    optional<L3Info>   l3; // populated after stripL3(), empty until then
    unique_ptr<L4Info> l4; // populated after stripL4(), null until then
    unique_ptr<L5Info> l5; // populated after stripL5(), null until then

    Packet(const uint8_t* packet_ptr, size_t packet_size, double time, int packet_id) {
        data.assign(packet_ptr, packet_ptr + packet_size);
        this->time = time;
        this->packet_id = packet_id;
    }

    // Parses the L2 header, stores metadata in l2, then erases those bytes from data so data begins at the L3 payload.
    void stripL2(const L2ParserRegistry& registry, int dlt) {
        l2 = registry.parse(dlt, data.data(), data.size());
        if (!l2) return;

        data.erase(data.begin(), data.begin() + l2->header_len);
    }

    // Parses the L3 header, stores metadata in l3, then erases those bytes from data so data begins at the L4 payload.
    // Must be called after stripL2() so that data starts at the IP header.
    void stripL3(const L3ParserRegistry& registry) {
        if (!l2) return;

        l3 = registry.parse(l2->proto, data.data(), data.size());
        if (!l3) return;

        data.erase(data.begin(), data.begin() + l3->header_len);
    }

    // Parses the L4 header, stores metadata in l4, then erases those bytes from data so data begins at the application payload.
    // Must be called after stripL3() so that data starts at the transport header.
    void stripL4(const L4ParserRegistry& registry) {
        if (!l3) return;

        l4 = registry.parse(l3->proto, data.data(), data.size());
        if (!l4) return;

        data.erase(data.begin(), data.begin() + l4->header_len);
    }

    // Parses the L5 header, stores metadata in l5, then erases those bytes from data so data begins at the application body.
    // Must be called after stripL4() so that data starts at the session-layer payload.
    // Only meaningful for TCP and UDP — ICMP has no session layer.
    void stripL5(const L5ParserRegistry& registry) {
        if (!l4) return;

        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        if (l4->protocol == IPProto::TCP) {
            const auto& t = static_cast<const TcpL4Info&>(*l4);
            src_port = t.src_port;
            dst_port = t.dst_port;
        }
        else if (l4->protocol == IPProto::UDP) {
            const auto& u = static_cast<const UdpL4Info&>(*l4);
            src_port = u.src_port;
            dst_port = u.dst_port;
        }
        else {
            return; // ICMP/ICMPv6 have no L5
        }

        l5 = registry.parse(src_port, dst_port, data.data(), data.size());
        if (!l5) return;

        data.erase(data.begin(), data.begin() + l5->header_len);
    }
};

// ==================== Helpers ====================

static void print_mac(const optional<MacAddr>& mac, const char* label) {
    cout << label << ": ";
    if (!mac) {
        cout << "N/A";
        return;
    }

    const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    const MacAddr& m = *mac;
    for (int i = 0; i < 6; i++) {
        if (i) cout << ':';
        cout << hex[(m[i] >> 4) & 0xF] << hex[m[i] & 0xF];
    }
}

static void print_ip(const optional<IPAddr>& ip, const char* label) {
    cout << label << ": ";
    if (!ip) {
        cout << "N/A";
        return;
    }

    const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    if (!ip->is_v6) {
        // dotted-decimal
        for (int i = 0; i < 4; i++) {
            if (i) cout << '.';
            cout << static_cast<int>(ip->v4[i]);
        }
    }
    else {
        // colon-hex groups
        for (int i = 0; i < 16; i += 2) {
            if (i) cout << ':';
            cout << hex[(ip->v6[i] >> 4) & 0xF] << hex[ip->v6[i] & 0xF]
                 << hex[(ip->v6[i+1] >> 4) & 0xF] << hex[ip->v6[i+1] & 0xF];
        }
    }
}

static const char* proto_name(IPProto p) {
    switch (p) {
        case IPProto::ICMP:   return "ICMP";
        case IPProto::TCP:    return "TCP";
        case IPProto::UDP:    return "UDP";
        case IPProto::ICMPv6: return "ICMPv6";
        default:              return "?";
    }
}

static void print_l4(const unique_ptr<L4Info>& l4) {
    if (!l4) {
        cout << " | no L4";
        return;
    }

    cout << " | ";

    switch (l4->protocol) {
        case IPProto::TCP: {
            const auto& t = static_cast<const TcpL4Info&>(*l4);
            cout << "TCP " << t.src_port << " -> " << t.dst_port
                 << " seq=" << t.seq << " ack=" << t.ack
                 << " win=" << t.window
                 << " flags=[";
            if (t.syn())   cout << "SYN ";
            if (t.ack_f()) cout << "ACK ";
            if (t.fin())   cout << "FIN ";
            if (t.rst())   cout << "RST ";
            if (t.psh())   cout << "PSH ";
            if (t.urg())   cout << "URG ";
            cout << "]";
            break;
        }
        case IPProto::UDP: {
            const auto& u = static_cast<const UdpL4Info&>(*l4);
            cout << "UDP " << u.src_port << " -> " << u.dst_port
                 << " len=" << u.length;
            break;
        }
        case IPProto::ICMP: {
            const auto& i = static_cast<const IcmpL4Info&>(*l4);
            cout << "ICMP type=" << static_cast<int>(i.type)
                 << " code=" << static_cast<int>(i.code);
            break;
        }
        case IPProto::ICMPv6: {
            const auto& i = static_cast<const ICMPv6L4Info&>(*l4);
            cout << "ICMPv6 type=" << static_cast<int>(i.type)
                 << " code=" << static_cast<int>(i.code);
            break;
        }
        default:
            cout << "unknown L4";
            break;
    }
}

static const char* tls_content_type_name(TlsContentType ct) {
    switch (ct) {
        case TlsContentType::ChangeCipherSpec: return "ChangeCipherSpec";
        case TlsContentType::Alert:            return "Alert";
        case TlsContentType::Handshake:        return "Handshake";
        case TlsContentType::ApplicationData:  return "ApplicationData";
        default:                               return "?";
    }
}

static void print_l5(const unique_ptr<L5Info>& l5) {
    if (!l5) {
        cout << " | no L5";
        return;
    }

    cout << " | ";

    switch (l5->protocol) {
        case L5Proto::HTTP: {
            const auto& h = static_cast<const HttpL5Info&>(*l5);
            if (h.kind == HttpKind::Request)
                cout << "HTTP " << h.method << " " << h.target << " " << h.version;
            else
                cout << "HTTP " << h.version << " " << h.status_code;
            break;
        }
        case L5Proto::TLS: {
            const auto& t = static_cast<const TlsL5Info&>(*l5);
            cout << "TLS " << tls_content_type_name(t.content_type)
                 << " v" << static_cast<int>(t.version_major) << "." << static_cast<int>(t.version_minor)
                 << " len=" << t.record_len;
            break;
        }
        case L5Proto::DNS: {
            const auto& d = static_cast<const DnsL5Info&>(*l5);
            cout << "DNS id=" << d.id
                 << (d.is_response ? " QR=response" : " QR=query")
                 << " qd=" << d.qdcount
                 << " an=" << d.ancount;
            break;
        }
        default:
            cout << "unknown L5";
            break;
    }
}

double now() {
    return chrono::duration<double>(
        chrono::system_clock::now().time_since_epoch()
    ).count();
}

// ==================== Main ====================

int main() {
    PacketSource pkt_src;
    L2ParserRegistry l2_registry;
    L3ParserRegistry l3_registry;
    L4ParserRegistry l4_registry;
    L5ParserRegistry l5_registry;

    const uint8_t* data;
    size_t size;

    int dlt = pkt_src.getLinkType(); // data link type will be the same for all packets on a given interface
    int packet_id = 1;
    double start = now();

    vector<Packet> packets;

    cout << "================== CAPTURE SESSION STARTED ==================" << endl;
    while (true) {
        if (pkt_src.getPacket(data, size)) {
            cout << "Packet (" << size << " bytes) received at " << now() - start << " seconds";

            Packet pkt(data, size, now() - start, packet_id++);
            pkt.stripL2(l2_registry, dlt);
            pkt.stripL3(l3_registry);
            pkt.stripL4(l4_registry);
            pkt.stripL5(l5_registry);

            if (pkt.l2) {
                cout << " | ";
                print_mac(pkt.l2->dst_mac, "dst");
                cout << "  ";
                print_mac(pkt.l2->src_mac, "src");
            } 
            else {
                cout << " | unknown link type " << dlt;
            }

            if (pkt.l3) {
                cout << " | ";
                print_ip(pkt.l3->src_ip, "src");
                cout << "  ";
                print_ip(pkt.l3->dst_ip, "dst");
                cout << " | proto: " << proto_name(pkt.l3->proto)
                     << " ttl: " << static_cast<int>(pkt.l3->ttl);
            } 
            else {
                cout << " | no L3";
            }

            print_l4(pkt.l4);
            print_l5(pkt.l5);

            if (pkt.l4)
                cout << " | payload: " << pkt.data.size() << " bytes";

            packets.push_back(move(pkt));
            cout << endl;
        }
    }

    return 0;
}