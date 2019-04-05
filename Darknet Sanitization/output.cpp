#include "include.h"

//
//Algorithmic function, centered on usage of destMap for Misconfiguration Equations
//
void ScanPCAPClass::pcap_dest_algorithm(void) {

	for (DEST_IP_IT dest_it = destMap.begin(); dest_it != destMap.end(); dest_it++) {

		//Probability of a destination being misconfigured algorithm
		long misc_denominator = 0;
		misc_denominator = (long)srcMap.size() * destMap.size();
		dest_it->second->misc_dest = (long double)dest_it->second->m_count / misc_denominator;

		//Probability of a destination being malicious algorithm
		//Calculating total number of Source IPs per Destination IP
		mean_count += dest_it->second->m_count;
	}

	//Calculating mean number of Source IPs per Destination IP
	mean = (double)mean_count / (double)destMap.size();

	for (DEST_IP_IT dest_it = destMap.begin(); dest_it != destMap.end(); dest_it++) {

		//Calculating Distance from mean per Destination IP
		double mean_diff = 0;
		//Calculating Variance
		mean_diff = (double)dest_it->second->m_count - (double)mean;
		dest_it->second->x_loc = (double)pow(mean_diff, 2);

		mean_loc += dest_it->second->x_loc;
	}

	//find variance and deviation of total set
	variance = (double)mean_loc / (double)destMap.size();
	deviation = sqrt(variance);

	for (DEST_IP_IT dest_it = destMap.begin(); dest_it != destMap.end(); dest_it++) {
		//e exponent
		double exponent = 0;
		//Calculating Distance from mean squared per Destination IP
		double exp_top = pow(dest_it->second->m_count - mean, 2);
		//Calculating Denominator of e side
		double exp_bot = 2 * variance;
		//Calculating Fraction of e side
		exponent = exp_top / exp_bot;
		exponent = -exponent;
		double exp_multi = exp(exponent);
		//Deviation
		double exp_dev = sqrt(2 * M_PI) * deviation;
		//Final Pmal Value, combining both sides
		dest_it->second->mal_dest = exp_multi / exp_dev;
	}

	return;
}

//
//Algorithmic function, centered on usage of srcMap for Misconfiguration Equations
//
void ScanPCAPClass::pcap_src_algorithm(int dark_ip_space) {

	//SrcMap Loop to begin calculating Pmisc/Pmal Values
	for (SRC_IP_IT src_it = srcMap.begin(); src_it != srcMap.end(); src_it++) {

		//Integer that stores the total number of destinations
		int u_dstsources = 0;

		DEST_IP_MAP *pDestMap = src_it->second->m_pDestMap;

		//T
		for (DEST_IP_IT dest_it = pDestMap->begin(); dest_it != pDestMap->end(); dest_it++) {
			u_dstsources++;
		}

		//Probability of a source being misconfigured algorithm
		long double exp_bot = 0;
		exp_bot = exp(1) - 1;
		//Calculating factorial of number of Destination IPs per Source IP
		for (int i = u_dstsources; i > 0; i--)
		{
			exp_bot *= (long double)i;
		}
		//Calculating fraction
		src_it->second->misc_src = (long double)1 / exp_bot;

		//Probability of a source being malicious algorithm
		//Calculating denominator
		src_it->second->mal_src = (long double)1 / dark_ip_space;

	}

	//SrcMap Loop to calculate final Pmisc/Pmal Values
	for (SRC_IP_IT src_it = srcMap.begin(); src_it != srcMap.end(); src_it++) {

		DEST_IP_MAP	*pDestMap = src_it->second->m_pDestMap;

		//DestMap linked to SrcMap Loop
		for (DEST_IP_IT dest_it = pDestMap->begin(); dest_it != pDestMap->end(); dest_it++) {

			//Multiplies all Pmisc(di) of destinations accessed by a source
			DEST_IP_IT mdest_it = destMap.find(dest_it->first);
			src_it->second->misc_src *= mdest_it->second->misc_dest;
			src_it->second->mal_src *= mdest_it->second->mal_dest;

		}

		//Natural Log to compare final probability
		src_it->second->misc_src = log(src_it->second->misc_src);
		src_it->second->misc_src = -src_it->second->misc_src;
		src_it->second->mal_src = log(src_it->second->mal_src);
		src_it->second->mal_src = -src_it->second->mal_src;

		//Final check for source IP, a greater misc_src value means the source is misconfigured
		double m_probability = 0;
		m_probability = (double)src_it->second->mal_src - (double)src_it->second->misc_src;
		if (m_probability > 0) {
			src_it->second->m_compare = 1;
		}
	}

	return;
}

//
//Second Packet Handler, compares each packet's header to the srcMap's m_compare value, if it is a misconfigured source
//it will print to seperate file from malicious sources
//
void ScanPCAPClass::oHandler(int num_packets, const string infile, const string miscfile, const string malfile) {

	//Supresses PcapPlusPlus messages for broken/incomplete packets
	//Remove comments if in order to override error output messages (May be necessary for polluted data sets)
	//pcpp::LoggerPP::supressErrors();

	//Integer to keep track of packet count, to be used to compare against runtime parameter
	int packet_count = 0;
	//Integer to keep track of unreadable packet count
	int broken_count = 0;

	//PcapPlusPLus interface that identifies file type between pcap/pcap-ng and creates the corresponding interface
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(infile.c_str());

	//Check that interface was created without error
	if (reader == NULL)
	{
		std::cout << "Error Creating PcapPlusPlus Interface!" << std::endl;
		exit(1);
	}

	//Opens pcap file for handling
	if (!reader->open())
	{
		std::cout << "Error Opening PcapPlusPlus Input File!" << std::endl;
		exit(1);
	}


	//PcapPlusPlus pcap file writer for misconfigured packets
	pcpp::PcapFileWriterDevice miscWriter(miscfile.c_str());

	//Opens pcap file for writing
	if (!miscWriter.open())
	{
		std::cout << "Error Opening PcapPlusPlus Misc. File!" << std::endl;
		exit(1);
	}

	//PcapPlusPlus pcap file writer for misconfigured packets
	pcpp::PcapFileWriterDevice malWriter(malfile.c_str());

	//Opens pcap file for writing
	if (!malWriter.open())
	{
		std::cout << "Error Opening PcapPlusPlus Mal. File!" << std::endl;
		exit(1);
	}

	//PcapPlusPlus empty packet container
	pcpp::RawPacket rawPacket;

	//Check that at least 1 packet is being printed
	if (0 != num_packets) {

		//Loops through the entire input pcap file
		while (reader->getNextPacket(rawPacket) && packet_count < num_packets)
		{
			//Checks that current packet is within the desired starting range
			if (0 == start_loc || o_current_loc >= start_loc) {

				//Iterate current packet number
				o_current_loc++;
				//Iterate packet count
				packet_count++;

				//Parse the current raw packet
				pcpp::Packet parsedPacket(&rawPacket);

				//Parse the IP layer of current parsed packet
				pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

				//Check that IP layer was read without error
				if (ipLayer != NULL)
				{
					//Retrieval of current parsed packet's source IP
					string sSrcIP = ipLayer->getSrcIpAddress().toString().c_str();
					SRC_IP_IT src_it = srcMap.find(sSrcIP);

					//Check current packet's source IP with srcMap values
					if (1 == src_it->second->m_compare) {
						miscWriter.writePacket(rawPacket);
					}
					else if (0 == src_it->second->m_compare) {
						malWriter.writePacket(rawPacket);
					}
					else {
						return;
					}
				}
				else {
					broken_count++;
					continue;
				}
			}
			//Packet is not within starting range, iterates to next packet without printing
			else {
				o_current_loc++;
			}
		}
	}
	else if (0 == num_packets) {

		//Loops through the entire input pcap file
		while (reader->getNextPacket(rawPacket))
		{
			//Checks that current packet is within the desired starting range
			if (0 == start_loc || o_current_loc >= start_loc) {

				//Iterate current packet number
				o_current_loc++;

				//Parse the current raw packet
				pcpp::Packet parsedPacket(&rawPacket);

				//Parse the IP layer of current parsed packet
				pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

				//Check that IP layer was read without error
				if (ipLayer != NULL)
				{
					//Retrieval of current parsed packet's source IP
					string sSrcIP = ipLayer->getSrcIpAddress().toString().c_str();
					SRC_IP_IT src_it = srcMap.find(sSrcIP);

					//Check current packet's source IP with srcMap values
					if (1 == src_it->second->m_compare) {
						miscWriter.writePacket(rawPacket);
					}
					else if (0 == src_it->second->m_compare) {
						malWriter.writePacket(rawPacket);
					}
					else {
						return;
					}
				}
				else {
					broken_count++;
					continue;
				}
			}
			//Packet is not within starting range, iterates to next packet without printing
			else {
				o_current_loc++;
			}
		}
	}

	//Error Output Statement for non ethernet packet count
	std::cout << std::endl << "Error Reading Ethernet Layer of " << broken_count << " Packets!" << std::endl;

	//Close input pcap file
	reader->close();

	//Close output pcap files
	miscWriter.close();
	malWriter.close();

	//Free memory used by reader
	delete reader;

	return;
}


//
//Output function, primary focus for debugging and testing of variables
//Loops through both destMap and srcMap to print values stored in each structure
//
void ScanPCAPClass::pcap_print() {

	//Walks through srcMap collecting count information
	for (SRC_IP_IT src_it = srcMap.begin(); src_it != srcMap.end(); src_it++) {

		if (1 == src_it->second->m_compare) {
			misc_source_count++;
			misc_packet_count += src_it->second->m_count;
		}
		else if (0 == src_it->second->m_compare) {
			mal_source_count++;
			mal_packet_count += src_it->second->m_count;
		}
		else {
			std::cout << "ERROR: SRC has invalid value! " << src_it->first.c_str() << std::endl;
			exit(1);
		}

	}

	//Global total
	int total_packet_count = tcpCount + udpCount + icmpCount;
	//Output statements to display global variables containing complete counts
	std::cout << std::endl << "Packet Distribution:" << std::endl;
	std::cout << "Total Ethernet Packet Count: " << total_packet_count << std::endl;
	std::cout << "Unique Source IPs: " << srcMap.size() << std::endl << "Unique Destination IPs: " << destMap.size() << std::endl;
	std::cout << "Packets: TCP: " << tcpCount << "     " << "UDP: " << udpCount << "     " << "ICMP: " << icmpCount << "     " << "Other: " << arpCount << std::endl;
	std::cout << "Number of Misconfigured Sources: " << misc_source_count << "     " << "Number of Misconfigured Packets: " << misc_packet_count << std::endl;
	std::cout << "Number of Malicious Sources: " << mal_source_count << "     " << "Number of Malicious Packets: " << mal_packet_count << std::endl << std::endl;

	return;
}
