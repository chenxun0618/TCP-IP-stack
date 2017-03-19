#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <assert.h>
#include <stdlib.h>
#include <netdb.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <time.h>

#define ACK 16
#define PSH 8
#define SYN 2
#define FIN 1

struct pseudo_header {
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint8_t reserved;
    uint8_t protocol;
    uint16_t pkt_len;
} __attribute__((packed));

struct arp {
    uint16_t hwType;
    uint16_t pcType;
    uint8_t hwLen;
    uint8_t pcLen;
    uint16_t op;
    uint8_t src_addr[6];
    uint8_t src_ip[4];
    uint8_t dst_addr[6];
    uint8_t dst_ip[4];
} __attribute__((packed));

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t send_seq;
    uint32_t recv_ack;
    uint16_t hdl_reserved_flags;            //header length (4 bits) & reserved bits (6 bits) & flags (6 bits)
    uint16_t window;
    uint16_t checksum;
    uint16_t unused_urgent_pointer;
} __attribute__((packed));

struct ip_hdr {
    uint8_t ver_hl;                         //version (4 bits) & header length (4 bits, in 4-byte words)
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t reserved_DF_MF_fr_offset;      //1 reserved bit & 1-bit DF flag & 1-bit MF & 13-bit fragment offset
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
} __attribute__((packed));

struct ether_header ether_hdr;

struct arp arp;

struct tcp_hdr tcp_hdr;

struct ip_hdr ip_hdr;

struct pseudo_header pseudo_hrd;

/*
 * initialize arp
 */
void initializeArp() {
    arp.hwType = htons(1);          //ethernet
    arp.pcType = htons(0x800);      //IP
    arp.hwLen = 6;
    arp.pcLen = 4;
    arp.op = htons(1);              //request
    uint8_t tmp[6];
    bzero(tmp, sizeof(tmp));

    memcpy(&arp.src_addr, &ether_hdr.ether_shost, sizeof(arp.src_addr));
    memcpy(&arp.dst_addr, tmp, sizeof(arp.dst_addr));
    memcpy(&arp.src_ip, &ip_hdr.src_ip, sizeof(arp.src_ip));
    memcpy(&arp.dst_ip, &ip_hdr.dst_ip, sizeof(arp.dst_ip));
}

/*
 * initialize ether_hdr
 * id: a student id (to generate the source mac)
 */
void initializeEtherHdr(char *id) {
    //sender ethernet address
    char ether_tmp[20];
    sprintf(ether_tmp, "02:0%.1s:%.2s:%.2s:%.2s:%.2s", id, id + 1, id + 3, id + 5, id + 7);
    memcpy(&ether_hdr.ether_shost, ether_aton(ether_tmp), sizeof(ether_hdr.ether_shost));

    //server ethernet address
    memcpy(&ether_hdr.ether_dhost, ether_aton("FF:FF:FF:FF:FF:FF"), sizeof(ether_hdr.ether_dhost));
}

/*
 * initialize tcp_hdr
 */
void initializeTCP_hdr() {
    srand(time(NULL));
    tcp_hdr.src_port = htons(rand());
    tcp_hdr.dst_port = htons(80);
    tcp_hdr.send_seq = 0;
    tcp_hdr.recv_ack = 0;
    tcp_hdr.hdl_reserved_flags = htons(5 << (16 - 4));
    tcp_hdr.window = htons(1400);
    tcp_hdr.checksum = 0;
    tcp_hdr.unused_urgent_pointer = 0;
}

/*
 * initialize ip_hdr
 * id: a student id (to generate the source ip)
 */
void initialize_ip_Hdr(char *id) {
    ip_hdr.ver_hl = 0x45;   //4:IPv4  5: five 4-byte words
    ip_hdr.tos = 0;
    ip_hdr.total_len = htons(5 * 4);
    ip_hdr.id = 0;
    ip_hdr.reserved_DF_MF_fr_offset = 0;
    ip_hdr.ttl = 0xff;
    ip_hdr.protocol = 6;
    ip_hdr.hdr_checksum = 0;

    //sender IP address, the remote machine has the network range 10.0.0.0/8
    char ip_tmp[15];
    struct in_addr src_ip;
    sprintf(ip_tmp, "10.%.3s.%.2s.%.2s", id + 2, id + 5, id + 7);
    if (inet_aton(ip_tmp, &src_ip) == 0) {
        fprintf(stderr, "Invalid IP address\n");
        exit(EXIT_FAILURE);
    }
    memcpy(&ip_hdr.src_ip, &src_ip, sizeof(ip_hdr.src_ip));

    //server IP address
    struct in_addr dst_ip;
    inet_aton("10.0.0.1", &dst_ip);
    memcpy(&ip_hdr.dst_ip, &dst_ip, sizeof(ip_hdr.dst_ip));
}

/*
 * initialize pseudo header
 */
void initializePseudoHdr() {
    memcpy(&pseudo_hrd.src_ip, &ip_hdr.src_ip, sizeof(pseudo_hrd.src_ip));
    memcpy(&pseudo_hrd.dst_ip, &ip_hdr.dst_ip, sizeof(pseudo_hrd.dst_ip));
    pseudo_hrd.reserved = 0;
    pseudo_hrd.protocol = 6;    //TCP
}

/*
 * checksum for tcp header & ip header
 * this function is referenced from http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
 */
uint16_t checksum(void *vdata, size_t length) {
    // Cast the data pointer to one that can be indexed.
    char *data = (char *) vdata;

    // Initialise the accumulator.
    uint32_t acc = 0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

/*
 * update the IP header
 * dataSize: size of the data to be sent
 */
void updateIP(int dataSize) {
    //total length
    ip_hdr.total_len = htons(sizeof(ip_hdr) + sizeof(tcp_hdr) + dataSize);

    //packet ID
    ip_hdr.id = ip_hdr.id + htons(1);

    //header checksum
    ip_hdr.hdr_checksum = 0;
    ip_hdr.hdr_checksum = checksum(&ip_hdr, sizeof(ip_hdr));
}

/*
 * update the TCP header
 * data: the data to be sent
 * seq: the new sequence number
 * ack: the new acknowledge number
 * flags: the new flags
 */
void updateTCP(void *data, uint32_t seq, u_int32_t ack, uint16_t flags) {
    uint16_t pktLen = 0;
    int dataSize = (int) strlen(data) * sizeof(char);
    unsigned char tmp[50 + dataSize];
    bzero(tmp, sizeof(tmp));

    //sequence number
    tcp_hdr.send_seq = seq;

    //acknowledgment number
    tcp_hdr.recv_ack = ack;

    //flags
    tcp_hdr.hdl_reserved_flags = htons((ntohs(tcp_hdr.hdl_reserved_flags) & 0xffc0) + flags);


    //checksum
    tcp_hdr.checksum = 0;
    pseudo_hrd.pkt_len = htons(sizeof(tcp_hdr) + dataSize);
    memcpy(tmp, &pseudo_hrd, sizeof(pseudo_hrd));
    pktLen += sizeof(pseudo_hrd);
    memcpy(tmp + pktLen, &tcp_hdr, sizeof(tcp_hdr));
    pktLen += sizeof(tcp_hdr);
    memcpy(tmp + pktLen, data, dataSize);
    pktLen += dataSize;
    tcp_hdr.checksum = checksum(tmp, pktLen);
}

/*
 * initialize an arp packet
 */
uint16_t initializeArpPacket(unsigned char *packet) {
    uint16_t pktLen = sizeof(pktLen);
    ether_hdr.ether_type = htons(0x0806);                       //ARP

    memcpy(packet + pktLen, &ether_hdr, sizeof(ether_hdr));     //ethernet header
    pktLen += sizeof(ether_hdr);
    memcpy(packet + pktLen, &arp, sizeof(arp));                 //arp
    pktLen += sizeof(arp);
    pktLen += 16;                                               //16 zeros
    pktLen = htons(pktLen - sizeof(pktLen));
    memcpy(packet, &pktLen, sizeof(pktLen));                    //length of the packet

    return ntohs(pktLen) + sizeof(pktLen);
}

/*
 * initialize a packet
 * packet: the buffer that contains the data
 * data: the data in the packet
 */
uint16_t initializePacket(unsigned char *packet, void *data) {
    uint16_t pktLen = sizeof(pktLen);

    bzero(packet, sizeof(packet));
    memcpy(packet + pktLen, &ether_hdr, sizeof(ether_hdr));     //ethernet header
    pktLen += sizeof(ether_hdr);
    memcpy(packet + pktLen, &ip_hdr, sizeof(ip_hdr));           //IP header
    pktLen += sizeof(ip_hdr);
    memcpy(packet + pktLen, &tcp_hdr, sizeof(tcp_hdr));         //TCP header
    pktLen += sizeof(tcp_hdr);
    memcpy(packet + pktLen, data, strlen(data) * sizeof(char)); //data
    pktLen += strlen(data) * sizeof(char);

    pktLen = htons(pktLen - sizeof(pktLen));
    memcpy(packet, &pktLen, sizeof(pktLen));                    //length of the packet

    return ntohs(pktLen) + sizeof(pktLen);
}

/*
 * update a packet
 * packet: the packet to be updated
 * packetSize: size of the packet/buffer with actual data (the actual size of the packet/buffer might be bigger)
 */
uint16_t updatePacket(unsigned char *packet, int packetSize) {
    struct ether_header server_size_ether_hdr;
    struct ip_hdr server_size_ip_hdr;
    struct tcp_hdr server_size_tcp_hdr;
    int index = 0, flags;
    uint32_t receivedDataSize;

    memcpy(&server_size_ether_hdr, packet, sizeof(server_size_ether_hdr));
    index += sizeof(server_size_ether_hdr);
    memcpy(&server_size_ip_hdr, packet + index, sizeof(server_size_ip_hdr));
    index += sizeof(server_size_ip_hdr);
    memcpy(&server_size_tcp_hdr, packet + index, sizeof(server_size_tcp_hdr));
    index += sizeof(server_size_tcp_hdr);

    receivedDataSize = (uint32_t) (packetSize - index);
    unsigned char data[receivedDataSize];
    bzero(data, sizeof(data));

    flags = ntohs(server_size_tcp_hdr.hdl_reserved_flags) & 0x3f;   //3f = 6, last 6 bits
    switch (flags) {
        case SYN + ACK:
            updateTCP(data, server_size_tcp_hdr.recv_ack, server_size_tcp_hdr.send_seq + htonl(1), ACK);
            updateIP(0);
            break;
        case ACK:
            if (server_size_tcp_hdr.recv_ack != tcp_hdr.send_seq + htonl(receivedDataSize)) {
                //resend
                printf("server only received %d bytes data\n", ntohl(server_size_tcp_hdr.recv_ack - tcp_hdr.send_seq));
            }
            updateTCP(data, server_size_tcp_hdr.recv_ack, server_size_tcp_hdr.send_seq, ACK);
            updateIP(0);
            break;
        case ACK + PSH:
            updateTCP(data, server_size_tcp_hdr.recv_ack, server_size_tcp_hdr.send_seq + htonl(receivedDataSize), ACK);
            updateIP(0);
            break;
        case FIN + ACK:
            updateTCP(data, server_size_tcp_hdr.recv_ack, server_size_tcp_hdr.send_seq + htonl(1), FIN + ACK);
            updateIP(0);
            break;
        default:
            printf("Received %d flag\n", flags);
            break;
    }

    return initializePacket(packet, data);

}

int main(int argc, char *argv[]) {
    int sockfd, port;
    unsigned char packet[1500];
    struct sockaddr_in server;
    struct hostent *host;


    assert(argc == 5);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    port = atoi(argv[2]);
    if ((host = gethostbyname(argv[3])) == NULL)
        errx(1, "no address associated with %s\n", argv[3]);

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr.s_addr, host->h_addr, host->h_length);

    bzero(packet, sizeof(packet));

    initializeTCP_hdr();
    initialize_ip_Hdr(argv[4]);
    initializeEtherHdr(argv[4]);
    initializeArp();
    initializePseudoHdr();

    if (connect(sockfd, (const struct sockaddr *) &server, sizeof(server)) != 0)
        errx(1, "%s\n", strerror(errno));

    uint16_t len;
    short isArp = 1, connected = 0, readyToReceiveData = 0, readyToCloseConnection = 0;
    ssize_t n;
    char data[1400];

    //send arp
    len = initializeArpPacket(packet);
    send(sockfd, packet, len, 0);

    while (recv(sockfd, &len, 2, 0) > 0) {       //get the length of the packet
        uint16_t currentPacketSize = 0;
        len = ntohs(len);
        bzero(packet, sizeof(packet));
        bzero(data, sizeof(data));
        while (currentPacketSize < len) {
            currentPacketSize += recv(sockfd, packet + currentPacketSize, len - currentPacketSize, 0);
        }
        if (isArp) {
            memcpy(&ether_hdr.ether_dhost, packet + sizeof(ether_hdr.ether_dhost), sizeof(ether_hdr.ether_dhost));
            ether_hdr.ether_type = htons(0x0800);   //change from arp to IPv4
            updateTCP(data, htonl(rand()), 0, SYN);
            updateIP(0);
            len = initializePacket(packet, data);
            isArp = 0;
        } else if (!connected) {
            //send Acknowledgement
            len = updatePacket(packet, currentPacketSize);
            send(sockfd, packet, len, 0);

            //send data request
            strcpy(data, "GET / HTTP/1.0\r\n\r\n");
            updateTCP(data, tcp_hdr.send_seq, tcp_hdr.recv_ack, ACK);
            updateIP((int) strlen(data) * sizeof(char));
            len = initializePacket(packet, data);
            connected = 1;
            readyToReceiveData = 1;
        } else if (readyToReceiveData) {
            //receive data
            bzero(packet, sizeof(packet));
            recv(sockfd, &len, 2, 0);       //get the packet length
            len = htons(len);
            n = recv(sockfd, packet, len, 0);

            //print data to stdout
            for (int i = 54; i < n; i++) {
                printf("%c", packet[i]);
            }
            //update packet to acknowledge the data
            len = updatePacket(packet, (int) n);
            readyToReceiveData = 0;
            readyToCloseConnection = 1;
        } else if (readyToCloseConnection) {
            len = updatePacket(packet, currentPacketSize);
            readyToCloseConnection = 0;
        } else {        //connection is closed
            break;
        }
        send(sockfd, packet, len, 0);
    }
    assert(close(sockfd) == 0);
    return 0;
}