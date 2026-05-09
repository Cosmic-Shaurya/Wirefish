# Packet Sniffer

A command-line tool that captures and decodes live network traffic across layers 2–5.
The most important details in each layer are displayed.

## Dependencies

- `libpcap`
- `g++` with C++17 support

## Build & Run

**Linux (Ubuntu/Debian)**
```bash
sudo apt install libpcap-dev g++
g++ -std=c++17 -o sniffer main.cpp -lpcap
sudo ./sniffer
```

**Linux (Fedora/RHEL)**
```bash
sudo dnf install libpcap-devel g++
g++ -std=c++17 -o sniffer main.cpp -lpcap
sudo ./sniffer
```

**macOS**
```bash
brew install libpcap
g++ -std=c++17 -o sniffer main.cpp -lpcap
sudo ./sniffer
```

**Windows (MSYS2/MinGW)**
```bash
pacman -S mingw-w64-x86_64-npcap-sdk mingw-w64-x86_64-gcc
g++ -std=c++17 -o sniffer main.cpp -lwpcap
./sniffer  # run as Administrator
```