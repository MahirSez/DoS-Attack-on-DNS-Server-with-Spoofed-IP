# DoS Attack to the DNS Server Using Spoofed IP Address



## 1. Setting Up DNS Server and Client

We used bind9 to use one VM as a DNS server. We run the command `service bind9 status` to check if the DNS server is working properly. The output is as follows:

<img src="/media/mahir/New Volume/The-Prestige-4-1/Computer-Security-Sessional-cse-406/dos-attack-project/report/final-report/bind9-status.png" style="zoom:67%;" />

We set up another VM as our client. In order to make sure that all of our client's DNS requests go through `DNS@192.168.0.105` we update the `/etc/resolv.conf` file in the client VM and change the address to `192.168.0.105`. Now, to check if the client is actually using `DNS@192.168.0.105` as its DNS server we run `nslookup google.com` on the client machine and check the output:

<img src="/media/mahir/New Volume/The-Prestige-4-1/Computer-Security-Sessional-cse-406/dos-attack-project/report/final-report/client-nslookup.png" style="zoom: 80%;" />



## 2. Using Socket to Send DNS Requests from the Attacker

Now, our primary target is to send an enormous amount of DNS requests to `DNS@192.168.0.105` from the attacker programmatically. We also need to spoof our IP address to hide our identity. We use raw socket to accomplish this. Raw sockets are very powerful in the sense that it gives the power to specify network level details such as source IP, destination IP etc.

### 2.1. Why Raw Socket?

It appears that we could use Datagram Sockets to easily create UDP packets and add the application layer DNS payload for out attack. But, the source IP resides in the network layer which is set by the kernel before sending out of the machine. Doing so, fails our purpose of spoofing the IP. Thus, we are forced to use raw sockets here. 

### 2.2. Creating Packet with Raw Socket

Using raw sockets gives us the responsibility to write the network, transport and application layer headers manually. 
