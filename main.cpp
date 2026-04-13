#include <cstdint>
#include <cstddef>
#include <memory>
#include <pcap.h>

#include <iostream>
#include <chrono>
#include <vector>

using namespace std;

class PacketSource {
    pcap_t* handle; // pointer to internal structure for packet capture in libpcap

public:
    PacketSource() {
        char errbuf[PCAP_ERRBUF_SIZE]; // PCAP_ERRBUF_SIZE is a constant that defines min size for safely handling errors

        pcap_if_t* alldevs; // linked list of network devices
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
            option_id ++;
        }

        int user_option = 0;
        while (user_option < 1 || user_option >= option_id) {
            cout << "Pick an option: ";
            cin >> user_option;
        }
        
        pcap_if_t* dev = alldevs;
        for (int i = 0; i < user_option - 1; i++) {
            dev = dev->next;
        }

        handle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf); // device, max bytes, promiscuous mode, read timeout in ms, errbuf

        /* NOTE:
            handle looks at first interface in linked list and starts capturing packets there.
            ideally, we should ask the user what interface they want to use.
            to be added later.
        */

        if (!handle) {
            std::cout << "Failed to open device\n";
        }

        pcap_freealldevs(alldevs); // destroys the linked list
    }

    bool getPacket(const uint8_t*& packet_ptr, size_t& packet_size) {
        if (!handle) return false;

        struct pcap_pkthdr* header; // metadata of packet from libpcap

        int res = pcap_next_ex(handle, &header, &packet_ptr); // returns 1 if success
        if (res != 1) return false;

        packet_size = header->len;
        return true;
    }

    ~PacketSource() {
        if (handle) pcap_close(handle); // close packet capture and free resources
    }
};

class Packet {
private:
    vector<uint8_t> data;
    double time;
    int packet_id;

public:
    Packet(const uint8_t* packet_ptr, size_t packet_size, double time, int packet_id) {
        data.assign(packet_ptr, packet_ptr + packet_size);
        this->time = time;
        this->packet_id = packet_id;
    }
};

double now() {
    return chrono::duration<double>(
        chrono::system_clock::now().time_since_epoch()
    ).count();
}

int main() {
    PacketSource pkt_src;
    const uint8_t* data;
    size_t size;

    int packet_id = 1;
    double start = now();

    vector<Packet> packets;
    
    cout << "================== CAPTURE SESSION STARTED ==================" << endl;
    while (true) {
        if (pkt_src.getPacket(data, size)) {
            cout << "Packet (" << size << " bytes) received at " << now() - start << " seconds";
            Packet pkt = Packet(data, size, now() - start, packet_id);
            packet_id ++;
            packets.push_back(pkt);
        }
        cout << endl;
    }

    return 0;
}