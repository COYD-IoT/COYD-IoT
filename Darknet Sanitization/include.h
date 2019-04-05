#ifndef _include_H_
#define _include_H_

//Standard C++ Libraries
#include <iostream>
#include <time.h>
#include <string.h>
#include <cmath>
#include <fstream>
#include <sstream>
#include <map>
#include <unordered_map>

//Libpcap(tcpdump)
#include <pcap.h>

//PcapPlusPlus
#include <Packet.h>
#include <PcapFileDevice.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Logger.h>

//Unix Socket Libraries for parsing packet data
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

using namespace std;

//Global declaration for the value of "Pi"
#define M_PI			3.14159265358979323846

#include <scanpcap.h>

#endif