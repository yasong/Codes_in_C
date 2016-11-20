#include "pcap.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"
#include "winsock2.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Ws2_32.lib")

#define LINE_LEN 16
#define MAX_ADDR_LEN 16

#define the Ethernet header
typedef struct ether_header{
	u_char ether_dst[6];        //destination address
	u_char ether_src[6];		//source address
	u_short ehter_type;			//ethernet type
}ether_header;

//typedef struct ip_address{
//	u_char byte1;
//	u_char byte2;
//	u_char byte3;
//	u_char byte4;
//}ip_address;
typedef struct ip_address{
	u_char addr[4];
}ip_address;

//ipv4
typedef struct ip_header{
#ifdef WORDS_BIGENDIAN
	u_char ip_version : 4, header_length : 4;
#else
	u_char header_length : 4, ip_version : 4;
#endif

	u_char ver_ihl;		//version and length
	u_char tos;			//quality of the service
	u_short tlen;		//total length
	u_short identification;		//
	u_short offset;		//group offset
	u_char ttl;			// time to live
	u_char proto;		//protocol
	u_short checksum;	//
	ip_address dst;		//destination address
	ip_address src;		//source address
	u_int op_pad;		//
}ip_header;

//tcp
typedef struct tcp_header{
	u_short dst_port;
	u_short src_port;
	u_int sequence;
	u_int ack;
#ifdef WORDS_BIGENDIAN
	u_char offset : 4, reserved : 4;
#else
	u_char reserved : 4, offset : 4;
#endif
	u_char flags;
	u_short windows_size;
	u_short checksum;
	u_short urgent_pointer;
}tcp_header;

//udp
typedef struct udp_header{
	u_short dst_port;
	u_short src_port;
	u_short length;
	u_short checksum;
}udp_header;

typedef struct icmp_header{
	u_char type;
	u_char code;
	u_short checksum;
	u_short identifier;
	u_short sequence;
	u_long ori_time;
	u_long rec_time;
	u_long tra_time;

}icmp_header;

typedef struct arp_header{
	u_short hardware_type;
	u_short protocol_type;
	u_char hardware_length;
	u_char protocol_length;
	u_short operation_code;
	u_char src_eth_addr[6];
	u_char src_ip_addr[4];
	u_char dst_eth_addr[6];
	u_char dst_ip_addr[4];
}arp_headr;
void contest_handle()
{

}
void hexdump(const u_char *pkt_content,u_int length)// , u_char length)
{
	//length = 16;
	//char *result;
	const u_char *data = (u_char *)pkt_content;
	//u_char length = strlen(data);
	u_char text[17] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	u_char i = 0;
	u_char j;
	for (i = 0; i < length; i++) {
		if (i % 16 == 0) printf("%08X  ", i);
		printf("%02X ", data[i]);
		text[i % 16] = (data[i] >= 0x20 && data[i] <= 0x7E) ? data[i] : '.';
		if ((i+1) % 8 == 0 || i+1 == length) printf(" ");
		if (i+1 == length && (i+1) % 16 != 0) {
			text[(i+1) % 16] = '\0';
			for (j = (i+1) % 16; j < 16; j++) printf("   ");
			if ((i+1) % 16 <= 8) printf(" ");
		}
		if ((i+1) % 16 == 0 || i+1 == length) printf("|%s|\n", text);
	}

}
void packet_handle_tcp(u_char *arg,
						const struct pcap_pkthdr *pkt_header,
						const u_char *pkt_content,u_int header_length)
{
	tcp_header *tcp_protocol;
	tcp_protocol = (tcp_header *)(pkt_content + 14 + 20);
	printf("++++++++++++++++++++++TCP Protocol+++++++++++++++++++++++\n");

	printf("Source Port: %i\n", ntohs(tcp_protocol->src_port));
	printf("Destination Port: %i\n", ntohs(tcp_protocol->dst_port));
	printf("Sequence number: %d\n", ntohl(tcp_protocol->sequence));
	printf("Acknowledgment number: %d\n", ntohl(tcp_protocol->ack));
	printf("header Length: %d\n", tcp_protocol->offset * 4);
	printf("Flags: 0x%.3x", tcp_protocol->flags);
	if (tcp_protocol->flags & 0x08) printf("(PSH)");
	if (tcp_protocol->flags & 0x10) printf("(ACK)");
	if (tcp_protocol->flags & 0x02) printf("(SYN)");
	if (tcp_protocol->flags & 0x20) printf("(URG)");
	if (tcp_protocol->flags & 0x01) printf("(FIN)");
	if (tcp_protocol->flags & 0x04) printf("(RST)");
	printf("\n");
	printf("Windows Size: %i\n", ntohs(tcp_protocol->windows_size));
	printf("Checksum: 0x%.4\n", ntohs(tcp_protocol->checksum));
	printf("Urgent Pointer: %i\n", ntohs(tcp_protocol->urgent_pointer));
	u_char *content = (u_char *)(pkt_content + 14 + 20 + 20);
	hexdump(content,header_length);
	contest_handle();


}
//udp
void packet_handle_udp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content)
{
	udp_header *udp_protocol;
	u_short dst_port;
	u_short src_port;
	u_short len;

	udp_protocol = (udp_header *)(pkt_content + 14 + 20);
	dst_port = ntohs(udp_protocol->dst_port);
	src_port = ntohs(udp_protocol->src_port);
	len = ntohs(udp_protocol->length);
}
//icmp
void packet_handle_icmp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content)
{
	icmp_header *icmp_protocol;
	u_short type;
	u_short len;
	u_int ori_time;
	u_int tra_time;
	u_int rec_time;

	icmp_protocol = (icmp_header *)(pkt_content + 14 + 20);
	printf("++++++++++++++++++++++TCP Protocol+++++++++++++++++++++++\n");
	len = sizeof(icmp_protocol);
	type = icmp_protocol->type;
	ori_time = icmp_protocol->ori_time;
	rec_time = icmp_protocol->rec_time;
	tra_time = icmp_protocol->tra_time;

}
//arp
void packet_handle_arp(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content)
{
	arp_headr *arp_protocol;
	u_short protocol_type;
	u_short hardware_type;
	u_short operation_code;
	u_char hardware_length;
	u_char protocol_length;

	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = pkt_header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

	printf("++++++++++++++++++++++ARP Protocol+++++++++++++++++++++++\n");
	arp_protocol = (arp_headr *)(pkt_content + 14);
	hardware_type = ntohs(arp_protocol->hardware_type);
	protocol_type = ntohs(arp_protocol->protocol_type);
	operation_code = ntohs(arp_protocol->operation_code);
	hardware_length = arp_protocol->hardware_length;
	protocol_length = arp_protocol->protocol_length;
	switch (operation_code)
	{
	case 1:
		printf("ARP请求协议\n");
		break;
	case 2:
		printf("ARP应答协议\n");
		break;
	case 3:
		printf("RARP请求协议\n");
		break;
	case 4:
		printf("RARP应答协议\n");
		break;
	default:
		break;
	}

}
//ip
void packet_handle_ip(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content)
{
	ip_header *ip_protocol;
	u_int header_length;
	u_char tos;
	u_short checksum;
	ip_address src;
	ip_address dst;
	u_char ttl;
	u_short tlen;
	u_short identification;
	u_short offset;

	printf("+++++++++++++++++++++++++++++++++++++IP Protocol+++++++++++++++++++++++++++\n");

	//SOCKADDR_IN source, dest;
	//char src_ip[MAX_ADDR_LEN], dst_ip[MAX_ADDR_LEN];

	ip_protocol = (ip_header *)(pkt_content + 14);
	//source.sin_addr.S_un.S_addr = inet_addr(ip_protocol->src);
	//dest.sin_addr.s_addr = ip_protocol->dst;
	header_length = ip_protocol->header_length * 4;
	checksum = ntohs(ip_protocol->checksum);
	tos = ip_protocol->tos;
	offset = ip_protocol->offset;
	ttl = ip_protocol->ttl;
	src = ip_protocol->src;
	dst = ip_protocol->dst;
	identification = ip_protocol->identification;
	tlen = ip_protocol->tlen;
	offset = ip_protocol->offset;

	//printf("%d%d%c%d%d%d", src, dst, ttl, identification, tlen, offset);
	switch (ip_protocol->proto)
	{
		case 6:
			packet_handle_tcp(arg, pkt_header, pkt_content,tlen);
			break;
		case 17:
			packet_handle_udp(arg, pkt_header, pkt_content);
			break;
		case 1:
			packet_handle_icmp(arg, pkt_header, pkt_content);
			break;
		default:
			break;
	}


}
//Ethernet
void packet_handle_eht(u_char *arg,
	const struct pcap_pkthdr *pkt_header,
	const u_char *pkt_content)
{
	ether_header *ethernet_protocol;
	u_short ethernet_type;
	u_char *mac;
	
	ethernet_protocol = (ether_header *)pkt_content;
	ethernet_type = ntohs(ethernet_protocol->ehter_type);

	printf("++++++++++++++++++++++Ethernet Protocol+++++++++++++++++++++++++\n");

	mac = ethernet_protocol->ether_src;

	printf("Source Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac,
		*(mac + 1),
		*(mac + 1),
		*(mac + 2),
		*(mac + 3),
		*(mac + 4),
		*(mac + 5));
	mac = ethernet_protocol->ether_dst;

	printf("Source Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		*mac,
		*(mac + 1),
		*(mac + 1),
		*(mac + 2),
		*(mac + 3),
		*(mac + 4),
		*(mac + 5));
	printf("Ethernet type: ");
	switch (ethernet_type)
	{
	case 0x0800:
		printf("%s", "IP");
		break;
	case 0x0806:
		printf("%s", "ARP");
		break;
	case 0x0835:
		printf("%s", "RARP");
		break;
	default:
		printf("%s", "Unknown Protocol!");
		break;
	}
	switch (ethernet_type)
	{
	case 0x0800:
		packet_handle_ip(arg, pkt_header, pkt_content);
		break;
	case 0x0806:
		packet_handle_arp(arg, pkt_header, pkt_content);
		break;
	case 0x0835:
		printf("++++++++++++++RARP Protocol++++++++++++++++++++++++\n");
		printf("RARP\n");
		break;
	default:
		printf("+++++++++++++++++Unknown Protocol++++++++++++++++++++\n");
		printf("Unknown Protocol\n");
		break;
	}
}
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	u_int j = 0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;


	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 跳转到已选中的适配器 */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
								65536,            // 要捕捉的数据包的部分 
													// 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
								PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
								1000,             // 读取超时时间
								NULL,             // 远程机器验证
								errbuf            // 错误缓冲池
								)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 获取数据包 */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0){

		if (res == 0)
			/* 超时时间到 */
			continue;

		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
		//hexdump(pkt_data,header->len);
		packet_handle_eht(NULL, header, pkt_data);
		//char temp[LINE_LEN + 1];
		//输出包
		/*for (j = 0; j < header->caplen; ++j)
		{
			printf("%.2x ", pkt_data[j]);
			if (isgraph(pkt_data[j]) || pkt_data[j] == ' ')
				temp[j % LINE_LEN] = pkt_data[j];
			else
				temp[j % LINE_LEN] = '.';

			if (j % LINE_LEN == 15)
			{
				temp[16] = '\0';
				printf("        ");
				printf("%s", temp);
				printf("\n");
				memset(temp, 0, LINE_LEN);
			}
		}
		printf("\n");*/
		/*if (pcap_sendpacket(adhandle, pkt_data, header->caplen)!=0)
		{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(adhandle));
		return -1;
		}*/
		//printf("Forward packets successfully!.\n");
		//break;
	}

	if (res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	return 0;
}
