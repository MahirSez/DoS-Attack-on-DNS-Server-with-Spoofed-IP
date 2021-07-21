# DoS Attack to the DNS Server Using Spoofed IP Address



## 1. Setting Up DNS Server and Client

We used bind9 to use one VM as a DNS server. We run the command `service bind9 status` to check if the DNS server is working properly. The output is as follows:

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/bind9-status.png?token=AHYCPXNIXJ6GZWXBYMIQJWLBAEKC2" style="zoom:67%;" />

We set up another VM as our client. In order to make sure that all of our client's DNS requests go through `DNS@192.168.0.105` we update the `/etc/resolv.conf` file in the client VM and change the address to `192.168.0.105`. Now, to check if the client is actually using `DNS@192.168.0.105` as its DNS server we run `nslookup google.com` on the client machine and check the output:

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/main/report/final-report/client-nslookup.png?token=AHYCPXNXIOZIEYJUHWESPWDBAEKBO" style="zoom: 80%;" />



## 2. Using Socket to Send DNS Requests from the Attacker

Now, our primary target is to send an enormous amount of DNS requests to `DNS@192.168.0.105` from the attacker programmatically. We also need to spoof our IP address to hide our identity. We use raw socket to accomplish this. Raw sockets are very powerful in the sense that it gives the power to specify network level details such as source IP, destination IP etc.

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

    

Next we tell the kernel that the IP header would be included in the payload by calling: 

```c
int yes = 1,
setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes))
```

Here, 

-   `sd` is the socket descriptor returned from the function `socket()`.
-   `IPPROTO_IP` defines that the option is about the IP level protocol.
-   `IP_HDRINCL` defines that the option is about IP header inclusion in the payload.



### 2.3. Creating the Payload

The basic structure of our payload would be as follows: 

<img src="https://raw.githubusercontent.com/MahirSez/DoS-Attack-on-DNS-Server-with-Spoofed-IP/66234c1bb6b80ddc2d3337e671ffbea3fac6fc1d/report/final-report/Payload%20Buffer.svg?token=AHYCPXMVFVG3UZ3KSEKAGG3A67UO4" style="zoom:80%;/>

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

As the DNS question would have variable length depending on the 

