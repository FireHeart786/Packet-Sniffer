#include <iostream>
#include <fstream>
#include <pcap.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Open the first available interface for packet capture
    handle = pcap_open_live(pcap_lookupdev(errbuf), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return -1;
    }

    // Compile and apply the filter expression
    char filter_exp[] = "tcp port 80 and src host 192.168.1.100";
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return -1;
    }

    // Capture packets indefinitely
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Parse packet headers and extract relevant information
    // Here we are printing out the packet type, source/destination addresses, payload, and timestamp
    std::cout << "Packet captured, length = " << pkthdr->len << std::endl;
    std::cout << "Packet type: " << packet[12] << packet[13] << std::endl;
    std::cout << "Source: " << packet[26] << "." << packet[27] << "." << packet[28] << "." << packet[29] << std::endl;
    std::cout << "Destination: " << packet[30] << "." << packet[31] << "." << packet[32] << "." << packet[33] << std::endl;
    std::cout << "Payload: " << std::string(reinterpret_cast<const char*>(packet + 54), pkthdr->len - 54) << std::endl;
    std::cout << "Timestamp: " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec << std::endl;

    // Save captured packets to a file for offline analysis
    std::ofstream outfile;
    outfile.open("captured_packets.pcap", std::ios_base::app | std::ios_base::binary);
    outfile.write(reinterpret_cast<const char *>(pkthdr), sizeof(struct pcap_pkthdr));
    outfile.write(reinterpret_cast<const char *>(packet), pkthdr->len);
    outfile.close();
}
