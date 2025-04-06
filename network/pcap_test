#include <stdio.h>
#include <pcap.h>
#include <ctype.h>
#include <netinet/ether.h>

//처음 이더넷 구조체를 분해한다.
struct ethheader{
	u_char ether_dhost[6]; //목적지의 MAC주소 //destination host임.
    u_char ether_shost[6];  // 출발지 MAC주소
    u_short ether_type; //프로토콜 확인
};

// IP 구조체를 분해한다.

struct ipheader {
    unsigned char      iph_ihl:4, //IP헤더 첫 4비트
                       iph_ver:4; //IP 헤더의 두번째 4비트
    unsigned char      iph_tos; //Type of service의 약자로 서비스의 종류를 의미함.
    unsigned short int iph_len; //IP Packet length -> 헤더와 데이터의 총 길이를 의미함.
    unsigned short int iph_ident; //식별자 -> 패킷을 구별할 떄 사용
    unsigned short int iph_flag:3, //패킷을 나눌 수 있는 지 여부등을 파악하기 위하여 3비트트
                       iph_offset:13; //조각위치 13비트트
    unsigned char      iph_ttl; //Time to Live-> 생존시간
    unsigned char      iph_protocol; //프로토콜을 의미한다. TCP는 6, UDP는 17을 의미
    unsigned short int iph_chksum; //checksum-> 오류 확인
    struct  in_addr    iph_sourceip; //출발지 IP
    struct  in_addr    iph_destip;   //도착지 IP
  };

//마지막으로 TCP구조체를 분해한다.

struct tcpheader {
    u_short tcp_sport;               // 출발 포트 주소
    u_short tcp_dport;               // 도착 포트 주소
    u_int   tcp_seq;                 // Sequence numeber 
    u_int   tcp_ack;                 // ack number 
    u_char  tcp_off:4;               // 헤더길이 
    u_char  tcp_reserved:4;          // 예약비트
    u_char  tcp_flags;               // flags
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 //윈도우 사이즈
    u_short tcp_sum;                 // checksum
    u_short tcp_urp;                 // ungent pointer
};
void tcp_message(const struct pcap_pkthdr *, const u_char *, struct ipheader *, struct tcpheader *);
//tcp_message를 출력하기 위하여 사용함.

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){ //packet capture 용도.

    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol == IPPROTO_TCP) { // tcp인지 확인인 tcp면 6이다.
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
        printf("Source MAC = %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
        printf("Destination MAC = %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

        printf("Source IP = %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Destination IP = %s\n", inet_ntoa(ip->iph_destip));
        printf("Source Port = %d\n", ntohs(tcp->tcp_sport));
        printf("Destination Port = %d\n", ntohs(tcp->tcp_dport));

        tcp_message(header,packet,ip,tcp);

        printf("\n");
    
    }
}

// TCP 메세지 출력
void tcp_message(const struct pcap_pkthdr *header, const u_char *packet, struct ipheader *ip, struct tcpheader *tcp){
    int tcp_header_len = (tcp-> tcp_off) * 4; // 길이 확인
    int ip_header_len = ip->iph_ihl * 4; //ip헤더 길이
    int total_header_size = sizeof(struct ethheader) + ip_header_len + tcp_header_len; 
    int payload_len = header->caplen - total_header_size;
    const u_char *payload = packet + total_header_size;
		// 메세지 출력
    for (int i = 0; i < payload_len && i < 100; i++) {
        if (isprint(payload[i])) {
            char c = payload[i];
            putchar(payload[i]);
        } else {
            putchar('.');
        }
    }
}


int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "pcap_open_live() 실패: %s\n", errbuf);
    return 1;
}

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}
