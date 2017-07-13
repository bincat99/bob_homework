#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>


#define DUMP_OFFSET 16

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

void parse_packet (const u_char* packet)
{

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
    hexdump (packet, header->caplen); 
    /* And close the session */
  }
  pcap_close(handle);
  return(0);
}
