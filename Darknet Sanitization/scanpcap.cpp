#include "include.h"

//
//Main Function - Uses libpcap functions to open a .pcap file for reading, loops through the file
//and calls the packet handler to process the packet headers and data as well as writes output to
//new .pcap files.
// 
int main ( int argc, char** argv ) {
	
	ScanPCAPClass scanpcap;

	//Calls function to display usage/help commands if user prompts for it
	string usage = argv[1];
	if (usage == "?" || usage == "-?" || usage == "help" || usage == "-help") {
		scanpcap.usage_commands();
		return 0;
	}

	//Converts first argument into integer to be used by packet handlers ; number of packets to be processed
	stringstream num_packets(argv[1]);
	int n_packets = 0;
	num_packets >> n_packets;

	//Converts second argument into integer to be used by packet handlers ; starting packet count
	stringstream loc_packets(argv[2]);
	loc_packets >> scanpcap.start_loc;

	//Converts third, fourth, fifth, and sixth arguments into strings to be used by packet handlers
	string CIDR = argv[3];
	char *infile = argv[4];
	char *miscfile = argv[5];
	char *malfile = argv[6];

	//Integer to store the combined value of total packets + starting packet count
	int t_packets = 0;
	if (0 != n_packets) {
		t_packets = n_packets + scanpcap.start_loc;
	}

	//Convert user input to integer for darknet size
	int dark_ip_space = 0;
	dark_ip_space = scanpcap.darknetSize(CIDR);

	//First pcap_t for initial packet processing
	pcap_t *pfile;
	char errbuff[PCAP_ERRBUF_SIZE];

	std::cout << "Starting Packet Processing..." << std::endl;

	//Opens pcap file for handling
	pfile = pcap_open_offline(infile, errbuff);
	if (pfile == NULL) {
		std::cout << "Opening of pcap file failed!" << std::endl << "Error: " << errbuff << std::endl;
	}

	//Loops through the pcap file stream to read captured packets
	if (pcap_loop(pfile, t_packets, pHandler, (u_char *) &scanpcap) < 0) {
		std::cout << "Reading of pcap file failed!" << std::endl << "Error: " << pcap_geterr(pfile) << std::endl;
		return 1; 
	} else {
		std::cout << "Packet Reading Complete!" << std::endl;
	}

	//Closes pcap file stream
	pcap_close(pfile);
	
	//Algorithm function calls
	std::cout << "Starting Packet Algorithms..." << std::endl;
	scanpcap.pcap_dest_algorithm();
	scanpcap.pcap_src_algorithm(dark_ip_space);
	std::cout << "Packet Algorithms Complete!" << std::endl;

	//Print new pcap files using PcapPlusPlus libraries
	std::cout << "Starting .pcap File Printing..." << std::endl;
	scanpcap.oHandler(n_packets, infile, miscfile, malfile);
	std::cout << "Packet Printing Complete!" << std::endl;

	//Final output
	std::cout << std::endl << "Starting Final Evaluations..." << std::endl;
	scanpcap.pcap_print();

	return 0;

}

