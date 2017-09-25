#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>



void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {

 int ip_len;
 int tcp_len;
 int count;
 int total_len;
 int payload_len;

 if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);  //packet check start
    if (res == 0) continue;
    if (res == -1 || res == -2) break;                 //packet check finish
    printf("%u bytes captured\n", header->caplen);

    //ethernet part	
    printf("Destination Address : %02x %02x %02x %02x %02x %02x\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);	     
    printf("Source Address      : %02x %02x %02x %02x %02x %02x\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);  
    
    //ipv4 part
    if((packet[12]==0x08)&&(packet[13]==0x00))  //if ipv4
    {
	printf("Source IP Address       : %d.%d.%d.%d\n",packet[26],packet[27],packet[28],packet[29]);
	printf("Destination IP Address  : %d.%d.%d.%d\n",packet[30],packet[31],packet[32],packet[33]);
	
	ip_len = (packet[14]&0xf) * 4;   // ip header length is expressed in word length type
	if (ip_len < 20) ip_len = 20;  
    //tcp part  
	if(packet[23]==0x6)                     //if tcp
	{
		printf("Source Port : %d\n", ((uint16_t)packet[14+(ip_len)]<<8) | (packet[14+ip_len+1]));
		printf("Destination Port : %d\n",((uint16_t)packet[16+(ip_len)]<<8) | (packet[16+ip_len+1]));
		
		tcp_len = (packet[14+ip_len+12]>>4) * 4 ;  // tcp header length is expressed in word length type 
		if(tcp_len < 20) tcp_len = 20;
		
		total_len = ((uint16_t)packet[16]<<8) | packet[17];
		payload_len = total_len - ip_len - tcp_len;
		
		printf("Payload : ");

    //payload part
		if(payload_len>0)
		{
			for(count = 0;count < 16; count++)
                	{
				if(count >= payload_len) break;
				
	                        printf("%02x ",packet[14+ip_len+tcp_len+count]);
                	}
			printf("\n");	
			
		}else{printf("No Payload!\n");}
		
			
	}else
	{
	    printf("Only Ethernet & IPv4! Not TCP!\n");
        }     
    }else
    {
	printf("Only Ethernet! Not IPv4!\n");
    }
    
    printf("---------------------------------------------------------\n");
}

  pcap_close(handle);
  return 0;
}









