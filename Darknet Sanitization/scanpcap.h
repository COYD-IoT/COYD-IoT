#ifndef _SCANPCAP_H_
#define _SCANPCAP_H_

//Global collections for Source and Destination IPs
struct SRC_INFO;
struct DEST_INFO;

//Hash Map that stores the Source IPs accessing a specific Destination IP
typedef unordered_map<string, SRC_INFO *>	SRC_IP_MAP;
typedef SRC_IP_MAP::iterator				SRC_IP_IT;

//Hash Map that stores the Destination IPs accessing a specific Source IPS
typedef unordered_map<string, DEST_INFO *>	DEST_IP_MAP;
typedef DEST_IP_MAP::iterator				DEST_IP_IT;

//Source IP Structure containing variables for misconfiguration probability calculations
struct SRC_INFO {
	DEST_IP_MAP		*m_pDestMap;
	int				m_count;
	//Equation 7 variable - probability that a source is misconfigured
	long double		misc_src;
	//Equation 8 variable - probability that a source is malicious
	long double		mal_src;
	//Equation 11 variable - equal to 1 if packet is misconfigured ; equal to 0 if packet is malicious
	int				m_compare;
};

//Destination IP Structure containing variables for misconfiguration probability calculations
struct DEST_INFO {
	SRC_IP_MAP		*m_pSrcMap;
	int				m_count;
	//Equation 1 variable - probability that a destination is misconfigured
	long double		misc_dest;
	//Equation 2 variable - distance from the mean value
	double			x_loc;
	//Equation 2 variable - probability that a destination is malicious
	long double		mal_dest;
};

//Primary structure containing all variables necessary for packet/protocol counts, calculations, and functions
class ScanPCAPClass {

public:

	//Constructor
	ScanPCAPClass() {
		tcpCount = 0;
		udpCount = 0;
		icmpCount = 0;
		arpCount = 0;
		misc_source_count = 0;
		mal_source_count = 0;
		misc_packet_count = 0;
		mal_packet_count = 0;
		start_loc = 0;
		p_current_loc = 0;
		o_current_loc = 0;
		mean_count = 0;
		mean = 0;
		mean_loc = 0;
		variance = 0;
		deviation = 0;
	};

	//Function declarations
	void	usage_commands(void);
	int		darknetSize(const string subnet);
	void	buildSrcCollection(const string sSrcIP, const string sDestIP);
	void	buildDestCollection(const string sSrcIP, const string sDestIP);
	void	pcap_print(void);
	void	pcap_dest_algorithm(void);
	void	pcap_src_algorithm(int dark_ip_space);
	
	//PcapPlusPlus Packet Handling function that will print output to new pcap files
	void	oHandler(int num_packets, const string infile, const string miscfile, const string malfile);

public:

	//Class variables for packet header protocol counts
	int	tcpCount;
	int udpCount;
	int icmpCount;
	int arpCount;

	//Class variables for calculation's resulting counts
	int misc_source_count;
	int mal_source_count;
	int misc_packet_count;
	int mal_packet_count;

	//Class variables for handler start location
	//Frame number of first packet to be used in algorithms
	int start_loc;
	//Frame number of current packet being processed by phandler
	int p_current_loc;
	//Frame number of current packet being processed by ohandler
	int o_current_loc;

	//Class variables for packet statistical analysis
	//total number of sources per destination, to be used to calculate mean
	int		mean_count;
	//mean of total number of sources per destination
	double	mean;
	//number of sources per destination, distance from the mean (difference)
	double	mean_loc;
	//variance of entire dataset
	double	variance;
	//deviation of entire dataset
	double	deviation;

	//Global unordered_map instance
	SRC_IP_MAP		srcMap;

	//Global unordered_map instance
	DEST_IP_MAP		destMap;

};

//Non-Class member function ; libpcap packet handler
void pHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char *packet);

#endif