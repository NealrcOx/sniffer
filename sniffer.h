#define MAX_BUFFER_SIZE 65535

#define IPV4 4

#define IPV6 6

#define IPV4STR "IPv4"

#define IPV6STR "IPv6"

#define ARPSTR "ARP"

#define IPV4_HEADER_LEN 20

//下面这个函数负责区分protocol
void processProtolcol(unsigned char procat);
