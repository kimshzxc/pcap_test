#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#define	ETHERTYPE_PUP	0x0200		/* PUP protocol */
#define	ETHERTYPE_IP	0x0008		/* IP protocol */
#define ETHERTYPE_ARP   0x0608		/* Addr. resolution protocol */

struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short ether_type;
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  struct ip *ip_header;
  struct ether_header *ether_header;
  struct tcphdr *tcp_header;


  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;


    printf("======================================================\n");
    printf("%u bytes captured\n", header->caplen);
    printf("\n");
/* 
    for(int i = 0;i< header->caplen;i++){
	if(i%16==0) printf("%04x : ",i);
	if(i%16==8) printf(" ");
	printf("%02x ", *(packet+i));
	if(i%16==15) printf("\n");
    }
*/
    ether_header = (struct ether_header*)packet;
    packet+=sizeof(struct ether_header);

    printf("\n");
    printf("[ Ethernet Header ]\n");
    printf("Source MAC Address = %02x:%02x:%02x:%02x:%02x:%02x\n",ether_header->ether_shost[0],ether_header->ether_shost[1],ether_header->ether_shost[2],ether_header->ether_shost[3],ether_header->ether_shost[4],ether_header->ether_shost[5]);
    printf("Destination MAC Address = %02x:%02x:%02x:%02x:%02x:%02x\n",ether_header->ether_dhost[0],ether_header->ether_dhost[1],ether_header->ether_dhost[2],ether_header->ether_dhost[3],ether_header->ether_dhost[4],ether_header->ether_dhost[5]); 
    printf("\n");
	if(ether_header->ether_type == short(ETHERTYPE_IP)){
		ip_header = (struct ip *)packet;
                packet += ip_header->ip_hl*4;
		printf("[ IPv4 Header ]\n");
		printf("Source IP Address = %s\n",inet_ntoa(ip_header->ip_src));
		printf("Destination IP Address = %s\n",inet_ntoa(ip_header->ip_dst));
		printf("Protocol Field = %d\n",ip_header->ip_p);
		printf("\n");

		if(ip_header->ip_p == 6){
			tcp_header = (struct tcphdr *)packet;
			packet+= int(tcp_header->th_off)*4;
			printf("[ TCP Header ]\n");
			printf("Source Port = %hu\n",htons(tcp_header->th_sport));
			printf("Destination Port = %hu\n",htons(tcp_header->th_dport));
			printf("\n");

			for(int i = 0; i< int(htons(ip_header->ip_len))-(ip_header->ip_hl*4+tcp_header->th_off * 4); i++){
				if(i==0) {
					printf("[ Data ] \n");
					printf("0x%04x : ",i);
				}
				else if(i==16) break;
				else if(i==8) printf(" ");
				printf("0x%02x ",packet[i]);
			}
			printf("\n");
		}
	}
	else{
		continue;
	}
  }

  pcap_close(handle);
  return 0;
}
