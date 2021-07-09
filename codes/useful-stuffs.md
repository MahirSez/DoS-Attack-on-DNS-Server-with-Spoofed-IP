## C Bit Fields

```c
    type-specifier declarator(opt) : constant-expression
```
*  The type-specifier for the `declarator` must be `unsigned int`, `signed int`, or `int`, and the `constant-expression` must be a nonnegative integer value.
* If the value is zero, the declaration has no `declarator`.
* Arrays of bit fields, pointers to bit fields, and functions returning bit fields are NOT allowed.
* The optional `declarator` names the bit field.
* Bit fields can only be declared as part of a structure
* The address-of operator (&) cannot be applied to bit-field components.
* Unnamed bit fields cannot be referenced, and their contents at run time are unpredictable. They can be used as "dummy" fields, for alignment purposes
* An unnamed bit field whose width is specified as 0 guarantees that storage for the member following it in the struct-declaration-list begins on an int boundary.

About memeory consumption:
https://stackoverflow.com/questions/824295/what-does-c-struct-syntax-a-b-mean/49722670#49722670


## Little-endian vs Big-endian

ittle-endian is when the least significant bytes are stored before the more significant bytes, and big-endian is when the most significant bytes are stored before the less significant bytes.


## IP header

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### IP header detials 

Ref - https://www.guru99.com/ip-header.html

### Raw Socket

* The IPv4 layer generates an IP header when sending a packet unless the `IP_HDRINCL` socket option is enabled on the socket. When it is enabled, the packet must contain an IP header.  For receiving, the IP header is always included in the packet.

* A protocol of `IPPROTO_RAW` implies enabled `IP_HDRINCL` and is able to send any IP protocol that is specified in the passed header.
* If `IP_HDRINCL` is specified and the IP header has a nonzero destination address, then the destination address of the socket is used to route the packet. 


### IP-header checksum

The checksum field is the 16-bit ones' complement of the ones' complement sum of all 16-bit words in the header. For purposes of computing the checksum, the value of the checksum field is zero.

Ref - https://en.wikipedia.org/wiki/IPv4_header_checksum

## testing bind9

```
nslookup <hostname> <optional:dns server>
```

## check who are connected to my router

```
nmap -sP netwrokIp/maskLen
```

## Kernel helps a lot!!

```
              ┌───────────────────────────────────────────────────┐
              │IP Header fields modified on sending by IP_HDRINCL │
              ├──────────────────────┬────────────────────────────┤
              │IP Checksum           │ Always filled in           │
              ├──────────────────────┼────────────────────────────┤
              │Source Address        │ Filled in when zero        │
              ├──────────────────────┼────────────────────────────┤
              │Packet ID             │ Filled in when zero        │
              ├──────────────────────┼────────────────────────────┤
              │Total Length          │ Always filled in           │
              └──────────────────────┴────────────────────────────┘
```

## DNS Request

Ref - https://www.binarytides.com/dns-query-code-in-c-with-winsock/

```
(RFC1035)

+---------------------+
| Header              |
+---------------------+
| Question            | the question for the name server
+---------------------+
| Answer              | RRs answering the question
+---------------------+
| Authority           | RRs pointing toward an authority
+---------------------+
| Additional          | RRs holding additional information
+---------------------+

```

### DNS Header

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     ID                        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR| Opcode    |AA|TC|RD|RA| Z      |  RCODE    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   QDCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   ANCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   NSCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   ARCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### DNS Query

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    QNAME                      /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QTYPE                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QCLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

## QNAME field

```
  /* Example:
     +---+---+---+---+---+---+---+---+---+---+---+
     | a | b | c | . | d | e | . | c | o | m | \0|
     +---+---+---+---+---+---+---+---+---+---+---+

     becomes:
     +---+---+---+---+---+---+---+---+---+---+---+---+
     | 3 | a | b | c | 2 | d | e | 3 | c | o | m | 0 |
     +---+---+---+---+---+---+---+---+---+---+---+---+
   */

```