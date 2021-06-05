#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h> // To invoke the libpcap library and use its functions.
#include <errno.h> //error number (error handling)
#include <sys/socket.h> //socket functions.
#include <netinet/in.h>
#include <arpa/inet.h>  //ftp,nameserver,telnet,ip basic methods.
#include <time.h>
#include <netinet/if_ether.h> 
#include <unistd.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[93m"
#define ANSI_COLOR_ORANGE  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_PURPLE  "\x1b[35m"
#define ANSI_COLOR_LIGHTGREY  "\x1b[37m"
#define ANSI_COLOR_DARKGREY  "\x1b[90m"
#define ANSI_COLOR_LIGHTRED  "\x1b[91m"
#define ANSI_COLOR_LIGHTGREEN  "\x1b[92m"
#define ANSI_COLOR_LIGHTBLUE  "\x1b[94m"
#define ANSI_COLOR_PINK  "\x1b[95m"
#define ANSI_COLOR_LIGHTCYAN  "\x1b[96m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define ARP_REQUEST 1	//ARP Request
#define ARP_RESPONSE 2	//ARP Response
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;		//Hardware type
  uint16_t ptype;		//Protocol type
  uint8_t hlen;			//Hardware address lenght (MAC)
  uint8_t plen;			//Protocol address length
  uint16_t opcode;		//Operation code (request or response)
  uint8_t sender_mac[6];	//Sender hardware address	
  uint8_t sender_ip[4];		//Sender IP address
  uint8_t target_mac[6];	//Target MAC address
  uint8_t target_ip[4];		//Target IP address
};


void alert_spoof(char *ip, char *mac){
	printf("\nAlert: Possible ARP Spoofing Detected. IP: %s and MAC: %s\n", ip, mac);
} 

int print_available_interfaces(){
	char error[PCAP_ERRBUF_SIZE];   //error buffer size is define as pcap.(256 bits)
	pcap_if_t *interfaces, *temp;   //pcap_if_t *interfaces works like as structure.(4 or 5 variables grouped together)
	int i = 0;        //count the no of devices.
	
	if(pcap_findalldevs(&interfaces, error) == -1){     //find all devices, -1 means no devices occur.
		printf("Cannot acquire the devices\n");
		return -1;
	}
	
	printf("The available interfaces are: \n");
	for(temp = interfaces; temp; temp=temp->next){
		printf("#%d: %s\n", ++i, temp->name);
	}
	return 0;
}

void print_version(){
	   printf("\t\t\t\t\t\t"ANSI_COLOR_CYAN" __    __       _____  _____  __          _        __                 "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t"ANSI_COLOR_CYAN"/ / /\\ \\ \\/\\  /\\\\_   \\/__   \\/__\\/\\/\\    /_\\    /\\ \\ \\ "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t"ANSI_COLOR_CYAN"\\ \\/  \\/ / /_/ / / /\\/  / /\\/_\\ /    \\  //_\\\\  /  \\/ /      "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t"ANSI_COLOR_CYAN" \\  /\\  / __  /\\/ /_   / / //__/ /\\/\\ \\/  _  \\/ /\\  /         "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t"ANSI_COLOR_CYAN"  \\/  \\/\\/ /_/\\____/   \\/  \\__/\\/    \\/\\_/ \\_/\\_\\ \\/     "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"                                                                      "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"   _      __    ___                                                   "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"  /_\\    /__\\  / _ \\                                               "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_CYAN" //_\\\\  / \\// / /_)/                                           "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"/  _  \\/ _  \\/ ___/                                                 "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"\\_/ \\_/\\/ \\_/\\/                                                  "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"                                                                      "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t"ANSI_COLOR_CYAN" __      __ _____  ___  ___  __  __                                   "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"/ _\\  /\\ \\ \\\\_   \\/ __\\/ __\\/__\\/__\\                        "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"\\ \\  /  \\/ / / /\\/ _\\ / _\\ /_\\ / \\//                          "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"_\\ \\/ /\\  /\\/ /_/ /  / /  //__/ _  \\                             "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"\\__/\\_\\ \\/\\____/\\/   \\/   \\__/\\/ \\_/                        "ANSI_COLOR_RESET"\n");
       printf("\t\t\t\t\t\t\t"ANSI_COLOR_CYAN"                                                                      "ANSI_COLOR_RESET"\n\t");

	printf("\t\t\t\t\t"ANSI_COLOR_BLUE"[---]"ANSI_COLOR_RESET"\t   "ANSI_COLOR_ORANGE"  Whiteman ARP Spoof Detector."ANSI_COLOR_RESET"\t"ANSI_COLOR_BLUE"[---]"ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t\t"ANSI_COLOR_BLUE"[---]"ANSI_COLOR_RESET"\t   "ANSI_COLOR_BLUE "  Created by:"ANSI_COLOR_RESET" "ANSI_COLOR_RED "Hari Sundar" ANSI_COLOR_RESET"\t\t"ANSI_COLOR_BLUE"[---]"ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t\t\t\t"ANSI_COLOR_BLUE "    Version:"ANSI_COLOR_RESET" "ANSI_COLOR_RED "0.1" ANSI_COLOR_RESET);
	printf("\n\t\t\t\t\t\t"ANSI_COLOR_GREEN"     Welcome to the Whiteman ARP Sniffer Toolkit."ANSI_COLOR_RESET"\n");
	printf("\n\t\t"ANSI_COLOR_GREEN"This tool will sniff for ARP packets in the interface and can possibly detect if there is an ongoing ARP spoofing attack. "ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t\t\t"ANSI_COLOR_GREEN"  This tool is still in a beta stage."ANSI_COLOR_RESET"\n");
}

void print_help(char *bin){

	printf("\n\t\t\t\t\t\t\t\t Available arguments: \n");
	printf("\t\t\t\t\t"ANSI_COLOR_MAGENTA " |------------------------------------------------------------------|"ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t"ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"-h or --help:\t\t\tPrint this help text.              "ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t"ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"-l or --lookup:\t\tPrint the available interfaces.    "ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t"ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"-i or --interface:\t\tProvide the interface to sniff on. "ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t"ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"-v or --version:\t\tPrint the version information.     "ANSI_COLOR_MAGENTA " |"ANSI_COLOR_RESET"\n");
	printf("\t\t\t\t\t"ANSI_COLOR_MAGENTA " |------------------------------------------------------------------|"ANSI_COLOR_RESET"\n");
	printf("\n\t\t\t"ANSI_COLOR_LIGHTBLUE"      Usage:" ANSI_COLOR_RESET" "ANSI_COLOR_YELLOW"%s"ANSI_COLOR_RESET" "ANSI_COLOR_LIGHTCYAN"-i"ANSI_COLOR_RESET" "ANSI_COLOR_LIGHTRED"<interface>"ANSI_COLOR_RESET" "ANSI_COLOR_LIGHTGREEN"[You can look for the available interfaces using -l/--lookup]"ANSI_COLOR_RESET"\n", bin);
	exit(1);
	
}

char* get_hardware_address(uint8_t mac[6]){
	char *m = (char*)malloc(20*sizeof(char));
		
	sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return m;
}

char* get_ip_address(uint8_t ip[4]){
	char *m = (char*)malloc(20*sizeof(char));
	sprintf(m, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	return m;
}

int sniff_arp(char *device_name){
	char error[PCAP_ERRBUF_SIZE];
	pcap_t* pack_desc;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct ether_header *eptr; //net/ethernet.h
	arp_hdr *arpheader = NULL;
	int i;
	u_char *hard_ptr;
	char *t_mac, *t_ip, *s_mac, *s_ip;
	int counter = 0;
	time_t ct, lt;
	long int diff = 0;
	pack_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
	if(pack_desc == NULL){
		printf("%s\n", error);
		print_available_interfaces();
		return -1;
	} else {
		printf("Listening on %s...\n", device_name);
	}
	while(1){
		packet = pcap_next(pack_desc, &header);
		if(packet == NULL){
			printf("Error: Cannot capture packet\n");
			return -1;
		} else {
			eptr = (struct ether_header*) packet;
			if (ntohs(eptr->ether_type) == ETHERTYPE_ARP){
				ct = time(NULL);
				diff = ct - lt;
				printf("ct: %ld; Diff: %ld; Counter: %d\n",ct, diff, counter);
				if(diff > 20){
					counter = 0;
				}
				arpheader = (arp_hdr*)(packet+14);
				printf("\nReceived an ARP packet with length %d\n", header.len);
				printf("Received at %s", ctime((const time_t*) &header.ts.tv_sec));
				printf("Ethernet Header Length: %d\n", ETHER_HDR_LEN);
				printf("Operation Type: %s\n", (ntohs(arpheader->opcode) == ARP_REQUEST) ? "ARP Request" : "ARP Response");
				s_mac = get_hardware_address(arpheader->sender_mac);
				s_ip = get_ip_address(arpheader->sender_ip);
				t_mac = get_hardware_address(arpheader->target_mac);
				t_ip = get_ip_address(arpheader->target_ip);
				printf("Sender MAC: %s\n", s_mac);
				printf("Sender IP: %s\n", s_ip);
				printf("Target MAC: %s\n", t_mac);
				printf("Target IP: %s\n", t_ip);
				printf("--------------------------------------------------------------");
				counter++;
				lt = time(NULL);
				if(counter > 10){
					alert_spoof(s_ip, s_mac);
				}
					
			}
		}
	}
	return 0;

}

int main(int argc, char *argv[]){

	if(access("/usr/bin/notify-send", F_OK) == -1){
		printf("Missing dependencies: libnotify-bin\n");
		printf("Please run: sudo apt-get install libnotify-bin");
		printf("\n");
		print_version();
		exit(-1);
	}
	
	if(argc < 2 || strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0){
		print_version();
		print_help(argv[0]);
	} else if(strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0){
		print_version();
		exit(1);
	} else if(strcmp("-l", argv[1]) == 0 || strcmp("--lookup", argv[1]) == 0){
		print_available_interfaces();
	} else if(strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0){
		if(argc < 3){
			printf(ANSI_COLOR_LIGHTRED"Error:"ANSI_COLOR_RESET" Please provide an interface to sniff on. Select from the following.\n");
			printf("--------------------------------------------------------------------------\n");
			print_available_interfaces();
			printf("\nUsage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", argv[0]);
		} else {
			sniff_arp(argv[2]);
		}
			
			
	} else {
		printf("Invalid argument.\n");
		print_help(argv[0]);
	}
	return 0;
}