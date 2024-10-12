
#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
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
    //create array of size 256 for all 256 different unique octet values
    int octet_counts[256];
    //initalize every element to 0
    for (int i = 0; i <256; i++) {
        octet_counts[i]=0;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ip* ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        unsigned char* ip_addr = (unsigned char*)&ip_header->ip_src;
        //increase the value at the corresponding indice of octet_counts by 1 
        octet_counts[ip_addr[3]]=octet_counts[ip_addr[3]]+1;
    }
    //loop through octet_counts
    for (int i = 0; i <256; i++) {
        //print indice(octet) and count at that indice(octet)
        printf("Last Octet %d:%d \n",i,octet_counts[i]);
    }
    pcap_close(handle);
    return 0;
}
