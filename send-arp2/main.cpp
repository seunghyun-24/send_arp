#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

//
#include <stdio.h>
#include <string.h> /* for strncpy */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

//
#include <arpa/inet.h>  ///< getsocknam
#include <unistd.h>     ///< close

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

//참고 : https://www.geekpage.jp/en/programming/linux-network/get-macaddr.php
//참고 : https://yogyui.tistory.com/entry/CLinux%EC%97%90%EC%84%9C-%EB%84%A4%ED%8A%B8%EC%9B%8C%ED%81%AC-%EC%96%B4%EB%8C%91%ED%84%B0-MAC-Address-%EA%B0%80%EC%A0%B8%EC%98%A4%EA%B8%B0

Mac get_my_mac_address(char* dev){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    Mac Mac_address = (uint8_t*)ifr.ifr_hwaddr.sa_data;

    return Mac_address;
};

//참고 : https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
//참고 : https://stackoverflow.com/questions/49335001/get-local-ip-address-in-c
Ip get_my_ip_address(char* dev){
    int fd;
    struct ifreq ifr;
    uint32_t ip_address;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char*)ifr.ifr_name, dev, IFNAMSIZ - 1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);

    ip_address = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr).s_addr);

    return ip_address;
};

int send_arp(pcap_t* handle, Mac ethernet_DesMac, Mac ethernet_SrcMac, u_short req, Mac arp_SrcMac, u_long arp_SrcIp, Mac arp_TargetMac, u_long arp_TargetIp) {
	EthArpPacket packet;

	packet.eth_.dmac_ = ethernet_DesMac;
	packet.eth_.smac_ = ethernet_SrcMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	
	packet.arp_.op_ = req;
	packet.arp_.smac_ = arp_SrcMac;
	packet.arp_.sip_ = arp_SrcIp;
	packet.arp_.tmac_ = arp_TargetMac;
	packet.arp_.tip_ = arp_TargetIp;

	return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    Mac my_mac_address;
    my_mac_address = get_my_mac_address(dev);

    Ip my_ip_address;
    my_ip_address = get_my_ip_address(dev);

    Ip sender_ip = Ip(argv[2]);

    Ip target_ip = Ip(argv[3]);

	/*
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = my_mac_address;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = my_mac_address;
	packet.arp_.sip_ = htonl(my_ip_address);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	*/

	int res = send_arp(handle, Mac("ff:ff:ff:ff:ff:ff"), my_mac_address, htons(ArpHdr::Request), my_mac_address, htonl(my_ip_address), Mac("00:00:00:00:00:00"), htonl(sender_ip));

	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        
        pcap_close(handle);
        return -1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

	while(1){ //pcap-test code
		int next = pcap_next_ex(handle, &header, &packet);

		if (next==0) continue;
		if (next == PCAP_ERROR || next == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", next, pcap_geterr(handle));
			break;
		}

		res = send_arp(handle, Mac("ff:ff:ff:ff:ff:ff"), my_mac_address, htons(ArpHdr::Request), my_mac_address, htonl(my_ip_address), Mac("00:00:00:00:00:00"), htonl(sender_ip));

		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        
       		pcap_close(handle);
        	return -1;
    	}
	}

	pcap_close(handle);
}

