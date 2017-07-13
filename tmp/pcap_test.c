#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#define DUMP_OFFSET 16
#define MAC_DST_OFFSET 0
#define MAC_SRC_OFFSET 6
#define IS_DST 0
#define IS_SRC 1 
#define ETHERTYPE_OFFSET 12
#define PAYLOAD_OFFSET 
#define IP_SRC_OFFSET
#define IP_DST_OFFSET
#define TCP_SRC_PORT
#define TCP_DST_PORT

void hexdump (const u_char *packet, bpf_u_int32 len)
{
  unsigned i = 0;

  while (i < len)
  {
    //const char* dump_format = "%8d: %x%x %x%x %x%x %x%x\t%8s\n"
    printf("%08x: ", i);
    
    unsigned j = 0;
    while (j < DUMP_OFFSET)
    {
      if ((i + j < len))
        printf ("%02x", 0xff & (char) packet[i+j]);
      else 
        printf ("  ");

      if ((i + j + 1< len))
        printf ("%02x ", 0xff & (char) packet[i+j+1]); 
      else
        printf ("   ");
      j += 2;
    }

    j = 0;
    while (j < DUMP_OFFSET)
    {
      char c = (char) packet[i+j];

      
      if (c >= 0x20 && c <0x7f)
        putchar (c);

      else 
        putchar ('.');

      j++;

      if (! (i + j < len))
        break;
    }
    puts ("");
    i += 0x10;
  }
}

void print_mac (char* mac, int t)
{
  /* TODO: make it enum */
  int i = 0;
  int len = 6;

  if (t == IS_SRC) 
    printf ("MAC_ADDR_SRC = ");
  else if (t == IS_DST) 
    printf ("MAC_ADDR_DST = ");
  else
  {
    printf ("FUCK ERROR\n");
    exit (-1);
  }
    
  for (i = 0; i < len; i++)
    printf ("%02X:", mac[i] & 0xff);
  printf ("\x08 ");
  puts ("");
}

void parse_eth_packet (const u_char* packet)
{
  char mac_dst[6]; 
  char mac_src[6]; 
  short eth_type;

  /* get mac destination address */
  memcpy (mac_dst, packet + MAC_DST_OFFSET, 6);

  /* get mac source address */
  memcpy (mac_src, packet + MAC_SRC_OFFSET, 6);

  /* get ethertype address */
  memcpy ((char*)&eth_type, packet + ETHERTYPE_OFFSET, 2);
  eth_type = ntohs (eth_type);

  print_mac (mac_dst, IS_DST);
  print_mac (mac_src, IS_SRC);
  printf("%d\n", eth_type);
}

int main(int argc, char *argv[])
{
  pcap_t *handle;     /* Session handle */
  char *dev;      /* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
  struct bpf_program fp;    /* The compiled filter */
  char filter_exp[] = "port 80 or port 443";  /* The filter expression */
  bpf_u_int32 mask;   /* Our netmask */
  bpf_u_int32 net;    /* Our IP */
  struct pcap_pkthdr *header;  /* The header that pcap gives us */
  const u_char *packet;   /* The actual packet */

  /* Define the device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return(2);
  }
  /* Find the properties for the device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }
  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }    
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  while (1)
  {
    /* Grab a packet */
    int res;
    res = pcap_next_ex(handle, &header, &packet);
    /* Print its length */
    //printf("res -> %d\n", res);
    printf("Jacked a packet with length of [%x]\n", header->caplen);

    if (res > 0)
    {
      parse_eth_packet (packet);
      hexdump (packet, header->caplen); 
    }
  }
  /* And close the session */
  pcap_close(handle);
  return(0);
}
