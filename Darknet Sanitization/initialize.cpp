#include "include.h"

//
//Outputs programs help commands when prompted
//
void ScanPCAPClass::usage_commands(void) {
	std::cout <<
		"Misconfigured Packet Cleansing with scanpcap.o Argument Guide:" << std::endl <<
		"Usage: scanpcap.o <NumPackets> <StartPos> <CIDR> <InFile> <OutFile1> <OutFile2>" << std::endl <<
		"NumPackets : Number of packets to process (0 = entire data set)" << std::endl <<
		"StartPos   : Packet to start processing (0 = start of input file)" << std::endl <<
		"CIDR       : CIDR size of data set - [/8, /13, /24] networks are supported" << std::endl <<
		"InFile     : File path for .pcap input data set" << std::endl <<
		"OutFile1   : File path to print .pcap misconfigured packets" << std::endl <<
		"OutFile2   : File path to print .pcap malicious packets" << std::endl;
	return;
}

//
//Converts second user input from subnet size to integer value of possible IP sizes to be used in algorithms
//
int ScanPCAPClass::darknetSize(const string subnet) {

	//"/8" subnets = 16,777,216 total IPs minus 2 (broadcast and network IPs)
	//"/13" subnets = 524,288 total IPs minus 2 (broadcast and network IPs)
	//"/24" subnets = 256 total IPs minus 2 (broadcast and network IPs)
	if (subnet == "/8") {
		return 16777214;
	}
	else if (subnet == "/13") {
		return 524286;
	}
	else if (subnet == "/24") {
		return 254;
	}
	else if (subnet == "exit" || subnet == "quit") {
		exit(1);
	}
	else {
		string net_size_retry;
		std::cout << "Invalid User Parameter[3]! Please input a supported net space! [/8, /13, /24]" << std::endl;
		std::cout << "CIDR: ";
		cin >> net_size_retry;
		return darknetSize(net_size_retry);
	}

}

//
//Creates srcMap - containing source IP addresses and their corresponding sent packet destination addresses
//First is a string containing a source IP, second is a map containing the destination accessed by source IP
//
void ScanPCAPClass::buildSrcCollection(const string sSrcIP, const string sDestIP)
{
	//map::find returns an iterator to the element or map::end otherwise
	SRC_IP_IT src_it = srcMap.find(sSrcIP);

	//Creates new map if not already in collection and initializes its member variables
	if (src_it == srcMap.end()) {

		pair<SRC_IP_IT, bool>  status;

		SRC_INFO *pSrcInfo = new SRC_INFO;

		pSrcInfo->m_pDestMap = new DEST_IP_MAP;
		pSrcInfo->m_count = 0;
		pSrcInfo->misc_src = 0;
		pSrcInfo->mal_src = 0;
		pSrcInfo->m_compare = 0;

		status = srcMap.insert(SRC_IP_MAP::value_type(sSrcIP, pSrcInfo));

		if (!status.second) {
			std::cout << "ERROR: Failed to add source IP to SRC collection, terminating!" << std::endl;
			exit(1);
		}

		src_it = status.first;

	}

	//Increment source specific destination count
	src_it->second->m_count += 1;

	//Link destination IP to source IP
	DEST_IP_MAP *pDestMap = src_it->second->m_pDestMap;

	DEST_IP_IT dest_it = pDestMap->find(sDestIP);

	//New map initialization
	if (dest_it == pDestMap->end()) {

		pair<DEST_IP_IT, bool>  status;

		DEST_INFO *pDestInfo = new DEST_INFO;
		pDestInfo->m_count = 0;
		pDestInfo->m_pSrcMap = NULL;
		pDestInfo->misc_dest = 0;
		pDestInfo->x_loc = 0;
		pDestInfo->mal_dest = 0;

		status = pDestMap->insert(DEST_IP_MAP::value_type(sDestIP, pDestInfo));

		if (!status.second) {
			std::cout << "ERROR: Failed to add destination IP to DEST collection, terminating!" << std::endl;
			exit(1);
		}

		dest_it = status.first;

	}

	//Increment destination count
	dest_it->second->m_count += 1;

	return;

}

//
//Creates destMap - containing destination IP addresses and their corresponding recieved packet source addresses
//First is a string containing a destination IP, second is a map containing the sources accessing this destination
//
void ScanPCAPClass::buildDestCollection(const string sSrcIP, const string sDestIP)
{
	//map::find returns an iterator to the element or map::end otherwise
	DEST_IP_IT dest_it = destMap.find(sDestIP);

	//Creates new map if not already in collection and initializes its member variables
	if (dest_it == destMap.end()) {

		pair<DEST_IP_IT, bool>  status;

		DEST_INFO *pDestInfo = new DEST_INFO;

		pDestInfo->m_pSrcMap = new SRC_IP_MAP;
		pDestInfo->m_count = 0;
		pDestInfo->misc_dest = 0;
		pDestInfo->x_loc = 0;
		pDestInfo->mal_dest = 0;

		status = destMap.insert(DEST_IP_MAP::value_type(sDestIP, pDestInfo));

		if (!status.second) {
			std::cout << "ERROR: Failed to add destination IP to DEST collection, terminating!" << std::endl;
			exit(1);
		}

		dest_it = status.first;

	}

	//Increment destination specific source address
	dest_it->second->m_count += 1;

	//Link source IP to destination IP
	SRC_IP_MAP *pSrcMap = dest_it->second->m_pSrcMap;

	SRC_IP_IT src_it = pSrcMap->find(sSrcIP);

	//New map initialization
	if (src_it == pSrcMap->end()) {

		pair<SRC_IP_IT, bool>  status;

		SRC_INFO *pSrcInfo = new SRC_INFO;
		pSrcInfo->m_count = 0;
		pSrcInfo->m_pDestMap = NULL;
		pSrcInfo->misc_src = 0;
		pSrcInfo->mal_src = 0;
		pSrcInfo->m_compare = 0;

		status = pSrcMap->insert(SRC_IP_MAP::value_type(sSrcIP, pSrcInfo));

		if (!status.second) {
			std::cout << "ERROR: Failed to add source IP to SRC collection, terminating!" << std::endl;
			exit(1);
		}

		src_it = status.first;

	}

	//Increment source count
	src_it->second->m_count += 1;

	return;

}


//
//Initial Packet Handler, uses arpanet libraries to retrieve source and destination IP addresses from packet headers
//and calls functions to create storage structure of these IP addresses
//
void pHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char *packet) {

	ScanPCAPClass *scanpcap = (ScanPCAPClass *)userData;

	//Checks that current packet is within the desired starting range
	if (0 == scanpcap->start_loc || scanpcap->p_current_loc >= scanpcap->start_loc) {
		//arpanet variables for ethernet packet processing
		const struct ether_header*		ethernetHeader = NULL;
		const struct ip*				ipHeader = NULL;

		char srcIP[INET_ADDRSTRLEN];
		char destIP[INET_ADDRSTRLEN];

		ethernetHeader = (struct ether_header*) packet;

		//ntohs() converts unsigned short integer from network byte order to host byte order to be processed
		//inet_ntop() converts IPv4 and IPv6 addresses from binary to human-readable text format
		//Includes incremented counts for protocol type and unknown packets
		if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {

			ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
			inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

			if (ipHeader->ip_p == IPPROTO_TCP) {
				scanpcap->tcpCount++;
			}
			else if (ipHeader->ip_p == IPPROTO_UDP) {
				scanpcap->udpCount++;
			}
			else if (ipHeader->ip_p == IPPROTO_ICMP) {
				scanpcap->icmpCount++;
			}

			scanpcap->buildSrcCollection(srcIP, destIP);
			scanpcap->buildDestCollection(srcIP, destIP);

		}
		else {

			scanpcap->arpCount++;

		}

		return;
	}
	//Packet is not within starting range, iterates to next packet without data retrieval
	else {
		scanpcap->p_current_loc++;
		return;
	}

}
