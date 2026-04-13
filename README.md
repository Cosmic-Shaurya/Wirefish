# Wirefish

A simple C++ packet sniffer built using **libpcap**.  
This project captures live network packets from a selected interface and stores them in memory for later analysis.

## Features

- Lists available network interfaces and lets user select capture device
- Captures live packets using libpcap
- Stores packet data safely (deep copy)
- Timestamping for each packet

## Requirements

- C++17 or later
- libpcap installed

## Compilation

- Use g++ main.cpp -o main -I"[FOLDER]\Include" -L"[FOLDER]\Lib\x64" -lwpcap
- [FOLDER] is the libpcap directory