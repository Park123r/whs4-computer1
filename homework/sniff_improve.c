#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
// TCP 헤더 길이를 계산해 주는 매크로 함수 정의
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)

/* 1. Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* 목적지 MAC 주소 */
  u_char  ether_shost[6]; /* 출발지 MAC 주소 */
  u_short ether_type;     /* 프로토콜 타입 (IP, ARP, RARP, etc) */
};

/* 2. IP Header */
struct ipheader {
  unsigned char      iph_ihl:4,     // IP 헤더 길이 4bit 
                     iph_ver:4;     // IP 버전 4bit   ihl + ver 1byte
  unsigned char      iph_tos;       // 서비스 유형 1 byte  
  unsigned short int iph_len;       // 전체 패킷 길이 2 byte
  unsigned short int iph_ident;     // 2byte
  unsigned short int iph_flag:3,    // 3비트
                     iph_offset:13; // 13비트   flag + offset 2byte
  unsigned char      iph_ttl;       // TTL 패킷 수명 떠돌지 않게 1byte
  unsigned char      iph_protocol;  // 프로토콜 타입 (TCP=6) 1byte
  unsigned short int iph_chksum;    // 체크섬 에러 체크용  2byte
  struct  in_addr    iph_sourceip;  // 출발지 IP 주소 
  struct  in_addr    iph_destip;    // 목적지 IP 주소 
}; // struct in_addr IPv4 주소를 저장하기 위한 표준 라이브러리 구조체 이름
		// ip 헤더 구조체를 선언하면 네트워크 패킷에 데이터가 흘러들어오는 물리적인 순서와 똑같은 순서로 변수를 적어야 한다.
/* 3. TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* 출발지 포트 번호 */
    u_short tcp_dport;               /* 목적지 포트 번호 */
    u_int   tcp_seq;                 
    u_int   tcp_ack;                 
    u_char  tcp_offx2;               /* TCP 헤더 길이 오프셋 */
    u_char  tcp_flags;
    u_short tcp_win;                 
    u_short tcp_sum;                 
    u_short tcp_urp;                 
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
// 패킷의 맨 앞 시작점은 이더넷 헤더로 시작한다. 메모리 시작 주소를 그대로 이더넷 구조체 크기만 큼 바라보게 한다.    
  struct ethheader *eth = (struct ethheader *)packet; 
	
	  // 1. MAC 주소 출력 구문
  printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  printf("     Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	
  if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷인 경우
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
		
    printf("\n==================================================\n");
    printf("           From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("             To: %s\n", inet_ntoa(ip->iph_destip));    

    /* 프로토콜 판별 */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            
            // 2. 헤더 크기 및 TCP 포인터 주소 계산
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)((u_char*)ip + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4;
            
             // 3. 포트 번호 출력
            printf("   Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Destination Port: %d\n", ntohs(tcp->tcp_dport));

            // 4. 데이터(Payload) 위치 및 크기 계산
            u_char *payload = (u_char*)tcp + tcp_header_len;
            int data_len = ntohs(ip->iph_len) - (ip_header_len + tcp_header_len);

            // 5. HTTP 데이터 출력
            if(data_len > 0){
                printf("HTTP Message\n");
                for (int i = 0; i < data_len; i++){
                    if((payload[i] >= 32 && payload[i] <= 126) || payload[i] == '\n' || payload[i] == '\r') {
                        printf("%c", payload[i]);
                    } else {
                        printf(".");
                    }
                }
                printf("\n-----------------------------------------\n");
            } else {
                printf(" No HTTP Message\n");
            }
            
            return;
            
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp"; // TCP 패킷 필터 설정
  bpf_u_int32 net;
  
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   
  return 0;
}