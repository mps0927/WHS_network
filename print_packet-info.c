#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include "myheader.h"

// char buffer[1024];
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* ehernet header*/
    struct ethheader *eth = (struct ethheader *)packet;
    if(ntohs(eth->ether_type) == 0x0800) // IPv4인지 확인인
    {
        /*ipheader를 가리킴*/
        struct ipheader *ip = (struct ipheader *) (packet + sizeof(struct ethheader));
        /* print MAC address */
        printf("[MAC]\n");
        printf("source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        /* print IP address */
        printf("[IP]\n");
        printf("source IP address: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("destination IP address: %s\n", inet_ntoa(ip->iph_destip));

        switch (ip->iph_protocol)
        {
            case IPPROTO_TCP:
                struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
                /*print TCP Port*/
                printf("[TCP]\n");
                printf("source port: %d\n", ntohs(tcp->tcp_sport));
                printf("destination port: %d\n", ntohs(tcp->tcp_dport));

                /*print msg*/
                const char *payload = (const char *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));
                /*payload_len = captured packet - headers */
                int payload_len = header->len - (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));
                if (payload_len > 0)
                {
                    printf("[MSG]\n");
                    printf("payload: ");
                    for (int i = 0; i < payload_len; i++)
                    {
                        printf("%02x ", (u_char)(payload[i]));
                    }
                    printf("\n");

                }
                else
                {
                    printf("[MSG]\n");
                    printf("There is No payload\n");
                }
                break;
                
            default:
                printf("There is No TCP protocol\n");

                break;
        }
        
    }
  



}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; //tcp protocol만 필터링링
    bpf_u_int32 net;
  
    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
  
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }
  
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
  
    pcap_close(handle);   //Close the handle
    return 0;
    
    
    return 0;
}