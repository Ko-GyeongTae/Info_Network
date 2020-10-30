#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 8192

struct Ether{
		uint8_t dst[6];
		uint8_t src[6];
		uint16_t type;		
};

struct IPHeader{
		uint8_t buf[26];
		uint8_t dst_ip[4];
		uint8_t src_ip[4];
};

void print_mac(uint8_t *mac){
		int i = 0;
		for(i = 0; i < 5; i++){
				printf("%02x:", mac[i]);
		}
		printf("%02x", mac[5]);
}

void print_IP(uint8_t *ip){
		int i = 0; 
		for(i = 0; i < 3; i++){
			 	printf("%3d.", ip[i]);
		}
		printf("%3d", ip[3]);	
}

uint16_t ntohs(uint16_t i){
		uint16_t a = (i & 0xff) << 8;
		uint16_t b = (i & 0xff00) >> 8;
		return a | b;
}

int main(){
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = NULL;
		handle = pcap_open_live("ens33", MAX_PACKET_SIZE, 0, 512, errbuf);
		if(handle == NULL) {
				printf("couldn't open dev device ens33\n");
				return -1;
		}
		printf("ens33 opened\n");

		struct pcap_pkthdr *header;
		const uint8_t *packet;
		int res;

		while((res = pcap_next_ex(handle, &header, &packet)) >= 0){
				if(res == 0)continue;
				struct Ether *pk = (struct Ether*)packet;
				pk->type = ntohs(pk->type);
				struct IPHeader *_pk = (struct IPHeader*)packet;
				/*
				print_mac(pk->src);
				printf(" -> ");
				print_mac(pk->dst);
				printf("\t");
				printf("%04x", pk->type);
				putchar('\n');
				*/
				printf("src IP : ");		
				print_IP(_pk->src_ip);
				printf(" -> ");
				printf("dst IP : ");
				print_IP(_pk->dst_ip);
				printf("\t");
				printf("%04x", pk->type);
				putchar('\n');
				
		}
		pcap_close(handle);
		return 0;
}
