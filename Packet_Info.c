#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <limits.h>

int PACKET_CNT = 1;
typedef struct in_addr IN_ADDR;

// For parsing Ethernet
typedef struct ether_head {
    int8_t dest_MAC[6];
    int8_t src_MAC[6];
    int8_t ether_type[2];
} ETHER_HEADER;

void print_MAC(uint8_t *MAC) {
    int i;
    for(int i = 0; i < 6; i++) {
        printf("%02x", MAC[i]);
        
        if (i != 5) {
            printf(":");
        }
    }
}

typedef enum ip_proto {IPv4, IPv6, ARP, ETC} IP_PROTOCOL; 

// For parsing IPv4
typedef struct ip_head {
    unsigned int IHL         : 4;
    unsigned int version     : 4;
    
    unsigned int ECN         : 2;
    unsigned int DSCP        : 6;

    uint16_t total_len;
    uint16_t identification;

    unsigned int frag_offset : 13;
    unsigned int flags       : 3;

    int8_t ttl;
    int8_t protocol;
    int16_t Checksum;
    IN_ADDR src_IP;
    IN_ADDR dest_IP;
} IP_HEADER;

// For parsing TCP
typedef struct tcp_head {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t useless : 4;
    uint8_t header_len : 4;
    uint8_t flag;
    uint16_t window_size;
    uint16_t checksum;
    
} TCP_HEADER;

// For parsing UDP
typedef struct udp_head {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t header_len;
    uint16_t checksum;
} UDP_HEADER;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    void *offset = (void*)packet;
    IP_PROTOCOL ether_type = ETC;
    
    printf("\n+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n");
    printf("=+=+=+=+=+=+=+=+=[PACKET %06d]=+=+=+=+=+=+=+=+=", PACKET_CNT);
    printf("\n+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n");
    
    // Frame
    ETHER_HEADER *ether = (ETHER_HEADER *)offset;
    printf("\n===================== Frame =====================\n");
    printf("Destination MAC address : ");
    print_MAC(ether->dest_MAC);
    printf("\nSource MAC address : ");
    print_MAC(ether->src_MAC);
    
    if (!memcmp(ether->ether_type, "\x08\x00", 2)) {
        printf("\nEhternet type : IPv4\n");
        ether_type = IPv4;
    } else if (!memcmp(ether->ether_type, "\x08\x06", 2)) {
        printf("\nEhternet type : ARP\n");
        ether_type = ARP;
    } else if (!memcmp(ether->ether_type, "\x86\xDD", 2)) {
        printf("\nEhternet type : IPv6\n");
        ether_type = IPv6;
    } else {
        printf("\nEhternet type : Protocols not included in [IPv4, IPv6, ARP]\n");
        ether_type = ETC;
    }
    
    offset = ether + 1;
    int8_t l3_protocol;
    if (ether_type == IPv4) {
        printf("\n===================== IPv4 =====================\n");
        IP_HEADER *ip = (IP_HEADER *)offset;
        printf("Version : %d\n", ip->version);
        printf("IHL : %d\n", ip->IHL);
        printf("Total Length : %d bytes\n", ntohs(ip->total_len));
        printf("Time to Live : %d\n", ip->ttl);
        
        l3_protocol = ip->protocol;
        
        if (l3_protocol == 6) {
            printf("Protocol : TCP\n");
        } else if (l3_protocol == 17) {
            printf("Protocol : UDP\n");
        } else if (l3_protocol == 1) {
            printf("Protocol : ICMP\n");
        } else {
            printf("Protocol : Protocols not included in [TCP, UDP, ICMP]\n");
        }
        
        printf("Destination IP Address : %s\n", inet_ntoa(ip->dest_IP));
        printf("Source IP Address : %s\n", inet_ntoa(ip->src_IP));

        offset = ((int8_t *)ip) + (ip->IHL) * 4;
    }
    
    if ( l3_protocol == 6 ) {
        printf("\n===================== TCP =====================\n");
        TCP_HEADER *tcp = (TCP_HEADER *) offset;
        printf("Destination Port : %d\n", ntohs(tcp->dest_port));
        printf("Source Port : %d\n", ntohs(tcp->src_port));
        printf("Sequence Number : %d\n", ntohl(tcp->seq_num));
        printf("Acknowledgment Number : %d\n", ntohl(tcp->ack_num));
        printf("Total Header Length : %d bytes (%d)\n", tcp->header_len * 4, tcp->header_len);

    } else if ( l3_protocol == 17) {
        printf("\n===================== UDP =====================\n");
        UDP_HEADER *udp = (UDP_HEADER *) offset;
        printf("Destination Port : %d\n", ntohs(udp->dest_port));
        printf("Source Port : %d\n", ntohs(udp->src_port));
        printf("Total Length : %d bytes\n", ntohs(udp->header_len));
    }
    
    PACKET_CNT++;
}


int main(void) {
    pcap_if_t *dev;
    char *net;
    char *mask;
    IN_ADDR addr;
    int ret;
    int user_input_flag = 0;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    char device_name[100];
    int32_t net_ID;
    int32_t mask_ID;
    
    // Find all network devices
    int err_check = pcap_findalldevs(&dev, errbuf);
    
    if(err_check == -1) {
    	printf("%s\n", errbuf);
    	return -1;
    }
    
    while (!user_input_flag) {
    	int cnt = 1;
    	int user_sel = -1;
    	char ch;
    	
    	pcap_if_t *temp = dev;
    	
    	// Let the user select the device
    	printf("===== DEVICE INFO =====\n");
    	while (temp->next != NULL) {
    		printf("[%d]Device name: %s\n", cnt, temp->name);
    		temp = temp->next;
    		cnt++;
    	}

   	printf("\nSelect device number >> ");
   	scanf("%d", &user_sel);

	temp = dev;
	for(;user_sel > 1; user_sel--) {
   	    temp = temp->next;
   	}
   	
   	// Outputs the name and network information of the selected device
   	printf("\n===== SELECTED DEVICE =====\n");
   	ret = pcap_lookupnet(temp->name, &net_ID, &mask_ID, errbuf);
   		
   	if(ret == -1) {
   	    printf("pcap_lookupnet ERROR : %s", errbuf);
   	    return -1;
   	}
   		
   	printf("Device name : %s\n", temp->name);
   	strcpy(device_name, temp->name);
   	
   	addr.s_addr = net_ID;
   	net = inet_ntoa(addr);
   	printf(" Network ID : %s\n", net);
   	
   	addr.s_addr = mask_ID;
   	mask = inet_ntoa(addr);
   	printf("    Mask ID : %s\n", mask);
   	
   	// Reconfirm that the selected device is correct or not
   	printf("\n+++ Do you want to use this device...? +++\n");
   	printf("If correct, enter [Y/y] : ");

   	char ch_check;
   	while( (ch = getchar()) != '\n' );
   	scanf("%c", &ch_check);
   	while( (ch = getchar()) != '\n' );
 
   	if (ch_check == 'Y' || ch_check == 'y') {
   	    user_input_flag = 1;
   	}
    }
    
    struct bpf_program fp;     
    pcap_t *pcd;

    pcd = pcap_open_live(device_name, BUFSIZ,  1, 1000, errbuf);
    if (pcd == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    
    // Let user set the filter
    printf("\n===== SET FILTER =====\n");
    printf("Set filter [ex) port 80, ip proto icmp] :");

    char filter_exp[100];
    scanf("%[^\n]s", filter_exp);
    
    if (pcap_compile(pcd, &fp, filter_exp, 0, net_ID) == -1) {
        printf("compile error\n");    
        exit(1);
    }
    
    if (pcap_setfilter(pcd, &fp) == -1) {
        printf("setfilter error\n");
        exit(0);    
    }
    
    // Packet capture
    pcap_loop(pcd, -1, callback, NULL);
    
    pcap_freealldevs(dev);
    pcap_close(pcd);
    return 0;
}
