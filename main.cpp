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
#include <fstream>

using namespace std;

// ==================== Byte utilities ====================

inline uint16_t read_u16_be(const uint8_t* p) { 
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

inline uint32_t read_u32_be(const uint8_t* p) { 
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline uint32_t read_u32_host(const uint8_t* p) { 
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

// ==================== L2 structures ====================

using MacAddr = array<uint8_t, 6>;

enum class EtherProto : uint16_t {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    VLAN = 0x8100,
    Unknown = 0xFFFF
};

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

struct L2Parser { 
    virtual optional<L2Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L2Parser() = default;

protected:
    static MacAddr read_mac(const uint8_t* p) {
        return {p[0], p[1], p[2], p[3], p[4], p[5]};
    }
};

struct EthernetParser : L2Parser {
    optional<L2Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 14) return nullopt;

        L2Info info;
        info.dst_mac = read_mac(pkt);
        info.src_mac = read_mac(pkt + 6);

        uint16_t etype = read_u16_be(pkt + 12);
        if (etype == static_cast<uint16_t>(EtherProto::VLAN)) {
            if (len < 18) return nullopt;
            etype = read_u16_be(pkt + 16);
            info.header_len = 18;
        }
        else {
            info.header_len = 14;
        }

        info.proto = (etype >= 0x0600) ? to_ether_proto(etype) : EtherProto::Unknown;
        return info;
    }
};

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

enum class IPProto : uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
    Unknown = 0xFF
};

static IPProto to_ip_proto(uint8_t v) {
    switch (v) {
        case 1:  return IPProto::ICMP;
        case 6:  return IPProto::TCP;
        case 17: return IPProto::UDP;
        case 58: return IPProto::ICMPv6;
        default: return IPProto::Unknown;
    }
}

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

    bool operator==(const IPAddr& o) const {
        if (is_v6 != o.is_v6) return false;
        return is_v6 ? v6 == o.v6 : v4 == o.v4;
    }
};

struct L3Info {
    optional<IPAddr> src_ip;
    optional<IPAddr> dst_ip;
    IPProto proto;
    uint8_t ttl;
    uint16_t total_len;
    size_t header_len;
};

struct L3Parser {
    virtual optional<L3Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L3Parser() = default;
};

struct IPv4L3Parser : L3Parser {
    optional<L3Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 20) return nullopt;

        uint8_t hdr_len = (pkt[0] & 0x0F);
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

struct IPv6L3Parser : L3Parser {
    optional<L3Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 40) return nullopt;

        L3Info info;

        uint8_t next = pkt[6];
        size_t offset = 40;

        while (true) {
            bool is_ext = (
                next == 0  ||
                next == 43 ||
                next == 44 ||
                next == 51 ||
                next == 60
            );

            if (!is_ext) break;

            if (offset + 2 > len) return nullopt;

            uint8_t hdr_next = pkt[offset];
            size_t ext_size = 0;

            if (next == 44) {
                ext_size = 8;
            } 
            else if (next == 51) {
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

        if (next == 50) {
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

struct L4Info {
    IPProto protocol;
    size_t header_len = 0;

    explicit L4Info(IPProto p) : protocol(p) {}
    virtual ~L4Info() = default;
};

struct TcpL4Info : L4Info {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint8_t flags;

    bool fin()   const { return flags & 0x01; }
    bool syn()   const { return flags & 0x02; }
    bool rst()   const { return flags & 0x04; }
    bool psh()   const { return flags & 0x08; }
    bool ack_f() const { return flags & 0x10; }
    bool urg()   const { return flags & 0x20; }

    TcpL4Info() : L4Info(IPProto::TCP) {}
};

struct UdpL4Info : L4Info {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;

    UdpL4Info() : L4Info(IPProto::UDP) {}
};

struct IcmpL4Info : L4Info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;

    IcmpL4Info() : L4Info(IPProto::ICMP) {}
};

struct ICMPv6L4Info : L4Info {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;

    ICMPv6L4Info() : L4Info(IPProto::ICMPv6) {}
};

struct L4Parser {
    virtual unique_ptr<L4Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L4Parser() = default;
};

struct TcpL4Parser : L4Parser {
    unique_ptr<L4Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 20) return nullptr;

        uint8_t data_offset = (pkt[12] >> 4);
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

enum class L5Proto : uint8_t {
    HTTP = 1,
    TLS = 2,
    DNS = 3,
    Unknown = 0xFF
};

struct L5Info {
    L5Proto protocol;
    size_t header_len = 0;

    explicit L5Info(L5Proto p) : protocol(p) {}
    virtual ~L5Info() = default;
};

enum class HttpKind : uint8_t { Request, Response };

struct HttpL5Info : L5Info {
    HttpKind kind;
    string method;
    string target;
    uint16_t status_code;
    string version;

    HttpL5Info() : L5Info(L5Proto::HTTP) {}
};

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
    uint16_t record_len;
    string sni; // populated for ClientHello only

    TlsL5Info() : L5Info(L5Proto::TLS) {}
};

struct DnsL5Info : L5Info {
    uint16_t id;
    bool is_response;
    bool is_truncated;
    bool recursion_desired;
    bool recursion_available;
    uint8_t opcode;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    DnsL5Info() : L5Info(L5Proto::DNS) {}
};

struct L5Parser {
    virtual unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const = 0;
    virtual ~L5Parser() = default;
};

struct HttpL5Parser : L5Parser {
    unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 8) return nullptr;

        size_t line_end = len;
        for (size_t i = 0; i + 1 < len; i++) {
            if (pkt[i] == '\r' && pkt[i + 1] == '\n') { line_end = i; break; }
            if (pkt[i] == '\n')                        { line_end = i; break; }
        }

        string first_line(reinterpret_cast<const char*>(pkt), line_end);

        auto info = make_unique<HttpL5Info>();

        if (first_line.substr(0, 5) == "HTTP/") {
            info->kind = HttpKind::Response;
            size_t sp1 = first_line.find(' ');
            if (sp1 == string::npos) return nullptr;

            info->version = first_line.substr(0, sp1);

            size_t sp2 = first_line.find(' ', sp1 + 1);
            string code_str = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
            info->status_code = static_cast<uint16_t>(stoi(code_str));
        }
        else {
            info->kind = HttpKind::Request;
            size_t sp1 = first_line.find(' ');
            if (sp1 == string::npos) return nullptr;

            info->method = first_line.substr(0, sp1);

            size_t sp2 = first_line.find(' ', sp1 + 1);
            if (sp2 == string::npos) return nullptr;

            info->target = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
            info->version = first_line.substr(sp2 + 1);
        }

        info->header_len = line_end + (line_end < len && pkt[line_end] == '\r' ? 2 : 1);
        return info;
    }
};

// Walks a TLS ClientHello to extract the SNI hostname from the server_name extension.
// Returns empty string if not found or if the record is not a ClientHello.
static string extract_sni(const uint8_t* pkt, size_t len) {
    // need record header(5) + handshake header(4) + client_hello fixed fields
    if (len < 5 + 4 + 2 + 32 + 1) return {};

    // must be Handshake record
    if (pkt[0] != 22) return {};
    // handshake type 1 = ClientHello
    if (pkt[5] != 1) return {};

    size_t off = 5 + 4; // skip record header and handshake header

    off += 2; // client_version
    off += 32; // random

    if (off >= len) return {};
    uint8_t sid_len = pkt[off++];
    off += sid_len; // session_id

    if (off + 2 > len) return {};
    uint16_t cipher_len = read_u16_be(pkt + off);
    off += 2 + cipher_len;

    if (off + 1 > len) return {};
    uint8_t comp_len = pkt[off++];
    off += comp_len;

    if (off + 2 > len) return {}; // no extensions
    uint16_t ext_total = read_u16_be(pkt + off);
    off += 2;

    size_t ext_end = off + ext_total;
    if (ext_end > len) return {};

    while (off + 4 <= ext_end) {
        uint16_t ext_type = read_u16_be(pkt + off);
        uint16_t ext_len  = read_u16_be(pkt + off + 2);
        off += 4;

        if (ext_type == 0) { // server_name extension
            // server_name_list_length(2) + name_type(1) + name_length(2) + name
            if (off + 5 > ext_end) break;
            off += 2; // list length
            off += 1; // name_type (0 = host_name)
            uint16_t name_len = read_u16_be(pkt + off);
            off += 2;
            if (off + name_len > ext_end) break;
            return string(reinterpret_cast<const char*>(pkt + off), name_len);
        }

        off += ext_len;
    }

    return {};
}

struct TlsL5Parser : L5Parser {
    unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const override {
        if (len < 5) return nullptr;
        if (pkt[1] != 3) return nullptr;

        TlsContentType ct = to_tls_content_type(pkt[0]);
        if (ct == TlsContentType::Unknown) return nullptr;

        auto info = make_unique<TlsL5Info>();
        info->header_len = 5;
        info->content_type = ct;
        info->version_major = pkt[1];
        info->version_minor = pkt[2];
        info->record_len = read_u16_be(pkt + 3);

        if (ct == TlsContentType::Handshake)
            info->sni = extract_sni(pkt, len);

        return info;
    }
};

struct DnsL5Parser : L5Parser {
    unique_ptr<L5Info> parse(const uint8_t* pkt, size_t len) const override {
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

// ==================== RTT Tracker ====================

// Key identifying one direction of a TCP flow (src -> dst)
struct FlowKey {
    IPAddr src_ip, dst_ip;
    uint16_t src_port, dst_port;

    bool operator==(const FlowKey& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        size_t h = 0;
        auto mix = [&](size_t v) { h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2); }; // hash function obtained externally

        if (!k.src_ip.is_v6) {
            uint32_t v; memcpy(&v, k.src_ip.v4.data(), 4); mix(v);
            memcpy(&v, k.dst_ip.v4.data(), 4); mix(v);
        } 
        else {
            for (int i = 0; i < 4; i++) {
                uint32_t v; memcpy(&v, k.src_ip.v6.data() + i*4, 4); mix(v);
                memcpy(&v, k.dst_ip.v6.data() + i*4, 4); mix(v);
            }
        }
        mix(k.src_port);
        mix(k.dst_port);
        return h;
    }
};

// pending seq entry
struct SeqEntry {
    uint32_t seq;
    double sent_time;
};

class RttTracker {
    // maps forward flow -> list of unacked seq numbers + send times
    unordered_map<FlowKey, vector<SeqEntry>, FlowKeyHash> pending;

    // smoothed RTT per flow
    unordered_map<FlowKey, double, FlowKeyHash> srtt;

public:
    // called when we see a TCP segment going forward
    void record_seq(const FlowKey& fwd, uint32_t seq, double t) {
        pending[fwd].push_back({seq, t});
        // cap backlog
        if (pending[fwd].size() > 256)
            pending[fwd].erase(pending[fwd].begin());
    }

    // called when we see an ACK on the reverse flow; returns RTT sample or -1
    double record_ack(const FlowKey& rev, uint32_t ack_num, double t) {
        FlowKey fwd{rev.dst_ip, rev.src_ip, rev.dst_port, rev.src_port};

        auto pit = pending.find(fwd);
        if (pit == pending.end()) return -1.0;

        double sample = -1.0;
        auto& entries = pit->second;

        for (auto it = entries.begin(); it != entries.end(); ) {
            // ACK covers anything with seq < ack_num (wrap-safe within 2^31)
            int32_t diff = static_cast<int32_t>(ack_num - it->seq);
            if (diff > 0) {
                double rtt = t - it->sent_time;
                if (rtt > 0) sample = rtt;
                it = entries.erase(it);
            } else {
                ++it;
            }
        }

        if (sample > 0) {
            auto sit = srtt.find(fwd);
            if (sit == srtt.end())
                srtt[fwd] = sample;
            else
                sit->second = 0.875 * sit->second + 0.125 * sample; // EWMA
        }

        return sample;
    }

    optional<double> get_srtt(const FlowKey& fwd) const {
        auto it = srtt.find(fwd);
        if (it == srtt.end()) return nullopt;
        return it->second;
    }
};

// ==================== PCAP Writer ====================

// writes a valid libpcap file that Wireshark can open
class PcapWriter {
    ofstream file;
    bool ok = false;

    void write_u16_le(uint16_t v) {
        file.put(static_cast<char>(v & 0xFF));
        file.put(static_cast<char>((v >> 8) & 0xFF));
    }
    void write_u32_le(uint32_t v) {
        file.put(static_cast<char>(v & 0xFF));
        file.put(static_cast<char>((v >> 8) & 0xFF));
        file.put(static_cast<char>((v >> 16) & 0xFF));
        file.put(static_cast<char>((v >> 24) & 0xFF));
    }

public:
    PcapWriter(const string& path, int dlt) {
        file.open(path, ios::binary);
        if (!file.is_open()) return;

        // global header
        write_u32_le(0xa1b2c3d4); // magic
        write_u16_le(2);// major version
        write_u16_le(4); // minor version
        write_u32_le(0); // timzone offset
        write_u32_le(0);  // timestamp accuracy
        write_u32_le(65535); // snap length
        write_u32_le(static_cast<uint32_t>(dlt));
        ok = true;
    }

    void write_packet(const vector<uint8_t>& raw, double timestamp) {
        if (!ok) return;

        uint32_t ts_sec  = static_cast<uint32_t>(timestamp);
        uint32_t ts_usec = static_cast<uint32_t>((timestamp - ts_sec) * 1e6);
        uint32_t cap_len = static_cast<uint32_t>(raw.size());

        write_u32_le(ts_sec);
        write_u32_le(ts_usec);
        write_u32_le(cap_len); // captured length
        write_u32_le(cap_len); // original length
        file.write(reinterpret_cast<const char*>(raw.data()), cap_len);
    }

    bool is_ok() const { return ok; }
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
    vector<uint8_t> raw; // original bytes for PCAP export
    double time;
    int packet_id;
    optional<L2Info>   l2;
    optional<L3Info>   l3;
    unique_ptr<L4Info> l4;
    unique_ptr<L5Info> l5;

    Packet(const uint8_t* packet_ptr, size_t packet_size, double time, int packet_id) {
        data.assign(packet_ptr, packet_ptr + packet_size);
        raw = data; // save before stripping
        this->time = time;
        this->packet_id = packet_id;
    }

    void stripL2(const L2ParserRegistry& registry, int dlt) {
        l2 = registry.parse(dlt, data.data(), data.size());
        if (!l2) return;
        data.erase(data.begin(), data.begin() + l2->header_len);
    }

    void stripL3(const L3ParserRegistry& registry) {
        if (!l2) return;
        l3 = registry.parse(l2->proto, data.data(), data.size());
        if (!l3) return;
        data.erase(data.begin(), data.begin() + l3->header_len);
    }

    void stripL4(const L4ParserRegistry& registry) {
        if (!l3) return;
        l4 = registry.parse(l3->proto, data.data(), data.size());
        if (!l4) return;
        data.erase(data.begin(), data.begin() + l4->header_len);
    }

    void stripL5(const L5ParserRegistry& registry) {
        if (!l4) return;

        uint16_t src_port = 0, dst_port = 0;

        if (l4->protocol == IPProto::TCP) {
            const auto& t = static_cast<const TcpL4Info&>(*l4);
            src_port = t.src_port; dst_port = t.dst_port;
        }
        else if (l4->protocol == IPProto::UDP) {
            const auto& u = static_cast<const UdpL4Info&>(*l4);
            src_port = u.src_port; dst_port = u.dst_port;
        }
        else return;

        l5 = registry.parse(src_port, dst_port, data.data(), data.size());
        if (!l5) return;
        data.erase(data.begin(), data.begin() + l5->header_len);
    }
};

// ==================== Helpers ====================

static void print_mac(const optional<MacAddr>& mac, const char* label) {
    cout << label << ": ";
    if (!mac) { cout << "N/A"; return; }

    const char hex[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    const MacAddr& m = *mac;
    for (int i = 0; i < 6; i++) {
        if (i) cout << ':';
        cout << hex[(m[i] >> 4) & 0xF] << hex[m[i] & 0xF];
    }
}

static void print_ip(const optional<IPAddr>& ip, const char* label) {
    cout << label << ": ";
    if (!ip) { cout << "N/A"; return; }

    const char hex[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    if (!ip->is_v6) {
        for (int i = 0; i < 4; i++) {
            if (i) cout << '.';
            cout << static_cast<int>(ip->v4[i]);
        }
    }
    else {
        for (int i = 0; i < 16; i += 2) {
            if (i) cout << ':';
            cout << hex[(ip->v6[i] >> 4) & 0xF] << hex[ip->v6[i] & 0xF]
                 << hex[(ip->v6[i+1] >> 4) & 0xF] << hex[ip->v6[i+1] & 0xF];
        }
    }
}

static const char* ether_proto_name(EtherProto p) {
    switch (p) {
        case EtherProto::IPv4: return "IPv4";
        case EtherProto::IPv6: return "IPv6";
        case EtherProto::ARP:  return "ARP";
        case EtherProto::VLAN: return "VLAN";
        default:               return "?";
    }
}

static void print_l2(const optional<L2Info>& l2) {
    if (!l2) { cout << " | no L2"; return; }
    cout << " | ";
    print_mac(l2->dst_mac, "dst");
    cout << "  ";
    print_mac(l2->src_mac, "src");
    cout << " | ether=" << ether_proto_name(l2->proto);
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

static void print_l3(const optional<L3Info>& l3) {
    if (!l3) { cout << " | no L3"; return; }
    cout << " | ";
    print_ip(l3->src_ip, "src");
    cout << "  ";
    print_ip(l3->dst_ip, "dst");
    cout << " | proto: " << proto_name(l3->proto)
         << " ttl: " << static_cast<int>(l3->ttl)
         << " total_len: " << l3->total_len;
}

static void print_l4(const unique_ptr<L4Info>& l4) {
    if (!l4) { cout << " | no L4"; return; }
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
            cout << "UDP " << u.src_port << " -> " << u.dst_port << " len=" << u.length;
            break;
        }
        case IPProto::ICMP: {
            const auto& i = static_cast<const IcmpL4Info&>(*l4);
            cout << "ICMP type=" << static_cast<int>(i.type) << " code=" << static_cast<int>(i.code);
            break;
        }
        case IPProto::ICMPv6: {
            const auto& i = static_cast<const ICMPv6L4Info&>(*l4);
            cout << "ICMPv6 type=" << static_cast<int>(i.type) << " code=" << static_cast<int>(i.code);
            break;
        }
        default:
            cout << "unknown L4";
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
    if (!l5) { cout << " | no L5"; return; }
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
            if (!t.sni.empty())
                cout << " sni=" << t.sni;
            break;
        }
        case L5Proto::DNS: {
            const auto& d = static_cast<const DnsL5Info&>(*l5);
            cout << "DNS id=" << d.id
                 << (d.is_response ? " QR=response" : " QR=query")
                 << " qd=" << d.qdcount << " an=" << d.ancount;
            break;
        }
        default:
            cout << "unknown L5";
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
    RttTracker rtt_tracker;

    const uint8_t* data;
    size_t size;

    int dlt = pkt_src.getLinkType();
    int packet_id = 1;
    double start = now();

    // open capture file
    string pcap_path = "capture.pcap";
    PcapWriter pcap_writer(pcap_path, dlt);
    if (pcap_writer.is_ok())
        cout << "Writing capture to: " << pcap_path << endl;
    else
        cout << "Warning: could not open capture file for writing" << endl;

    vector<Packet> packets;

    cout << "================== CAPTURE SESSION STARTED ==================" << endl;
    while (true) {
        if (pkt_src.getPacket(data, size)) {
            double t = now() - start;

            cout << "Packet (" << size << " bytes) received at " << t << " seconds";

            Packet pkt(data, size, t, packet_id++);

            // write raw bytes before stripping
            pcap_writer.write_packet(pkt.raw, now());

            pkt.stripL2(l2_registry, dlt);
            pkt.stripL3(l3_registry);
            pkt.stripL4(l4_registry);
            pkt.stripL5(l5_registry);

            // RTT tracking for TCP
            if (pkt.l4 && pkt.l4->protocol == IPProto::TCP && pkt.l3) {
                const auto& tcp = static_cast<const TcpL4Info&>(*pkt.l4);

                if (pkt.l3->src_ip && pkt.l3->dst_ip) {
                    FlowKey fwd{*pkt.l3->src_ip, *pkt.l3->dst_ip, tcp.src_port, tcp.dst_port};

                    // record outgoing seq
                    if (tcp.syn() || pkt.data.size() > 0)
                        rtt_tracker.record_seq(fwd, tcp.seq, now());    

                    // measure RTT from incoming ACK
                    if (tcp.ack_f()) {
                        FlowKey rev{*pkt.l3->dst_ip, *pkt.l3->src_ip, tcp.dst_port, tcp.src_port};
                        double sample = rtt_tracker.record_ack(rev, tcp.ack, now());
                        if (sample > 0)
                            cout << " | rtt_sample=" << (sample * 1000.0) << "ms";

                        auto srtt = rtt_tracker.get_srtt(rev);
                        if (srtt)
                            cout << " srtt=" << (*srtt * 1000.0) << "ms";
                    }
                }
            }

            if (!pkt.l2)
                cout << " | unknown link type " << dlt;
            else
                print_l2(pkt.l2);

            print_l3(pkt.l3);
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