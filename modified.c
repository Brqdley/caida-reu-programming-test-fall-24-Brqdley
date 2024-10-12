#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
//changed linux/if_ether to net/ethernet for macos
#include <net/ethernet.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    //changed iphdr to ip due to include change
    struct ip *ip_header;
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        //changed struct to ether_header due to change in the include 
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        //changed daddr to ip_dst due to change in the include
        //ip_header->ip_dst directly accesses ip_dst, which is already of type struct in_addr, eliminating the need for casting and dereferencing
        //moreover, previous code was trying to cast a value to a reference, which is incorrect, it needed &ip_header instead of ip_header to be correct
        printf("Packet %d: IP destination address: %s\n", ++packet_count,inet_ntoa(ip_header->ip_dst));
    }
    
    pcap_close(handle);
    return 0;
}
