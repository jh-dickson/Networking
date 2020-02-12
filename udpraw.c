#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <time.h>

#define PCKT_LEN 8192

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
    {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int sendUDP(const char *sourceIP, const char *sourcePort, const char *destIP, const char *destPort)
{
    u_int16_t src_port, dst_port;
    u_int32_t src_addr, dst_addr;
    src_addr = inet_addr(sourceIP);
    dst_addr = inet_addr(destIP);
    src_port = atoi(sourcePort);
    dst_port = atoi(destPort);

    int sd;
    char buffer[PCKT_LEN];
    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));

    struct sockaddr_in sin;
    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PCKT_LEN);

    //create raw socket
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0)
    {
        perror("socket() error");
        exit(2);
    }
    printf("OK: a raw socket is created.\n");

    //attempt to get permission from kernel to fill our own header
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(2);
    }
    printf("OK: socket option IP_HDRINCL is set.\n");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("Sending UDP\n");

    // fabricate the IP header
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 16;
    ip->tot_len  = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip->id       = htons(54321);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = src_addr;
    ip->daddr = dst_addr;

    // fabricate the UDP header
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr));

    // calculate the checksum for integrity
    ip->check = csum((unsigned short *)buffer,
                    sizeof(struct iphdr) + sizeof(struct udphdr));

    if (sendto(sd, buffer, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("Error: Unable to send packet.");
        exit(3);
    }
    printf("OK: one packet is sent.\n");

    close(sd);
    return 0;
}

int rcvPacket(const char *bindAddr, int bindPort)
{
    int rcv_socket;
    struct sockaddr_in sockstr;
    socklen_t socklen;

    char msg[256];
    ssize_t msglen;

    if ((rcv_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) 
    {
        perror("Error creating socket");
        return 1;
    }

    sockstr.sin_family = AF_INET;
    sockstr.sin_port = htons(bindPort);
    sockstr.sin_addr.s_addr = inet_addr(bindAddr);

    if (bind(rcv_socket, (struct sockaddr*) &sockstr, (socklen_t) sizeof(sockstr)) == -1) 
    {
        perror("bind");
        close(rcv_socket);
        return 1;
    }

    //set message buffer to zero before reading data
    memset(msg, 0, 256);

    if ((msglen = recv(rcv_socket, msg, (sizeof(struct iphdr) + sizeof(struct udphdr)), 0)) == -1) 
    {
        perror("Error recieving from socket");
        close(rcv_socket);
        return 1;
    }

    if (msglen <= (sizeof(struct iphdr) + sizeof(struct udphdr)))
    {
        printf("No message\n");
    }
    else 
    {
        msg[msglen - 1] = '\0';
        printf("Your msg _plus_ headers's size is: %s\n",
               msg + (sizeof(struct iphdr) + sizeof(struct udphdr)));
    }
    close(rcv_socket);

    return 0;
}

int sendICMP(const char *sourceIP, const char *sourcePort, const char *destIP, const char *destPort)
{   
    u_int16_t src_port, dst_port;
    u_int32_t src_addr, dst_addr;
    src_addr = inet_addr(sourceIP);
    dst_addr = inet_addr(destIP);
    src_port = atoi(sourcePort);
    dst_port = atoi(destPort);

    int sd;
    char buffer[PCKT_LEN];
    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));

    struct sockaddr_in sin;
    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PCKT_LEN);

    //create raw socket
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0)
    {
        perror("socket() error");
        exit(2);
    }
    printf("Created RAW socket\n");

    //attempt to get permission from kernel to fill our own header
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(2);
    }
    printf("OK: socket option IP_HDRINCL is set.\n");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("Sending ICMP\n");

    // fabricate the IP header
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 16;
    ip->tot_len  = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip->id       = htons(54321);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = src_addr;
    ip->daddr = dst_addr;

    // fabricate the "ICMP" header
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr));

    // calculate the checksum for integrity
    ip->check = csum((unsigned short *)buffer,
                    sizeof(struct iphdr) + sizeof(struct udphdr));

    if (sendto(sd, buffer, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        perror("Error: Unable to send packet.");
        exit(3);
    }
    printf("OK: one packet is sent.\n");

    close(sd);
    return 0;
}

int main(int argc, char const *argv[])
{
    if (strcmp(argv[1], "--help") == 0)
    {
        printf("Usage: %s <mode> <source/listen IP> <source/listen port> <target hostname/IP> <target port>\n", argv[0]);
        printf("Valid modes are -i: ICMP send, -u UDP send, -r Recieve any\n");
        exit(1);
    }

    //set appropriate vars from cli arguments
    const char *sourceIP = argv[2];
    const char *sourcePort = argv[3];
    const char *destIP = argv[4];
    const char *destPort = argv[5];

    printf("Source IP: %s\tSource Port: %s\n", sourceIP, sourcePort);
    printf("Destination IP: %s\tDestination Port: %s\n", destIP, destPort);

    if (strcmp("-i", argv[1]) == 0)
    {
        printf("Mode: ICMP Send\n");
        sendICMP(sourceIP, sourcePort, destIP, destPort);
    }
    else if (strcmp("-u", argv[1]) == 0)
    {
        printf("Mode: UDP Send\n");
        sendUDP(sourceIP, sourcePort, destIP, destPort);
    }
    else if (strcmp("-r", argv[1]) == 0)
    {
        printf("Mode: Recieve Any\n");
        rcvPacket(sourceIP, atoi(sourcePort));
    }
    else
    {
        printf("Unable to parse mode: %s\n", argv[1]);
        return 1;
    }

    return 0;
}