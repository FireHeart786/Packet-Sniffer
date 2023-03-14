# Packet-Sniffer
This C++ code is an example of how to use the pcap library to capture network traffic and filter it based on specific criteria. It captures packets that match the filter expression "tcp port 80 and src host 192.168.1.100" and then prints out information about the captured packets, including the packet type, source/destination addresses, payload, and timestamp. Additionally, the captured packets are saved to a file for offline analysis.

# warning
This Code is just for the Educational Purpose only the owner of this repo or code is not responsible for its misuse
# usage
compilation
     
     g++ capture.cpp -o capture -lpcap
     
Execution

     sudo ./capture
     sudo ./capture -i eth0
     sudo ./capture -f "tcp port 80 and src host 192.168.1.100"






