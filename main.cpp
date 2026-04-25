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

        info.proto = (etype >= 0x0600) ? static_cast<EtherProto>(etype) : EtherProto::Unknown;
        
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

        info.proto = static_cast<EtherProto>(read_u16_be(pkt + 14));
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
        size_t  hdr = static_cast<size_t>(hdr_len) * 4;
        if (hdr < 20 || len < hdr) return nullopt;

        L3Info info;
        info.header_len = hdr;
        info.total_len = read_u16_be(pkt + 2); 
        info.ttl = pkt[8];
        info.proto = static_cast<IPProto>(pkt[9]);
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
            info.proto = static_cast<IPProto>(next);
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
    optional<L2Info> l2; // populated after stripL2(), empty until then
    optional<L3Info> l3; // populated after stripL3(), empty until then

    Packet(const uint8_t* packet_ptr, size_t packet_size, double time, int packet_id) {
        data.assign(packet_ptr, packet_ptr + packet_size);
        this->time = time;
        this->packet_id = packet_id;
    }

    // Parses the L2 header, stores metadata in l2, then erases those bytes from data so data begins at the L3 payload.
    void stripL2(const L2ParserRegistry& registry, int dlt) {
        l2 = registry.parse(dlt, data.data(), data.size());
        if (!l2) return;

        // erase exactly the header bytes from the front
        data.erase(data.begin(), data.begin() + l2->header_len);
    }

    // Parses the L3 header, stores metadata in l3, then erases those bytes from data so data begins at the L4 payload.
    // Must be called after stripL2() so that data starts at the IP header.
    void stripL3(const L3ParserRegistry& registry) {
        if (!l2) return; // need L2 info to know which L3 proto to parse

        l3 = registry.parse(l2->proto, data.data(), data.size());
        if (!l3) return;

        data.erase(data.begin(), data.begin() + l3->header_len);
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
        case IPProto::ICMP: return "ICMP";
        case IPProto::TCP: return "TCP";
        case IPProto::UDP: return "UDP";
        case IPProto::ICMPv6: return "ICMPv6";
        default: return "?";
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
                     << " ttl: " << static_cast<int>(pkt.l3->ttl)
                     << " | L4 payload: " << pkt.data.size() << " bytes";
            } 
            else {
                cout << " | no L3";
            }

            packets.push_back(pkt);
            cout << endl;
        }
    }

    return 0;
}