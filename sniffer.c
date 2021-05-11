#include<unistd.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<errno.h>
#include<sys/socket.h>
#include<fcntl.h>
#include<netinet/in.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<arpa/inet.h>
#include<dirent.h>
#include<sys/select.h>
#include<netdb.h>
#include<net/if.h>
#include<net/if_arp.h>
#include<linux/if_ether.h>
#include"sniffer.h"



int main(void)
{
  //建立一个当前目录下的嗅探日志snifflog
  DIR * dir = NULL;
  if((dir=opendir("./snifflog")) == NULL)
  {
    //若scanlog不存在,创建目录
    system("mkdir ./snifflog/");
  }
  else
  {
    //snifflog存在,删除目录下的所有文件
    closedir(dir);
    system("rm  ./snifflog/*");
  }

  int sock, n,k = 0;
  char buffer[MAX_BUFFER_SIZE];
  unsigned char *iphead, *ethead;
  struct ifreq ifr;

  sock = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL)); //ETH_P_IP就会收不到自己发出去的包
  //检查套接字是否创建
  if(sock < 0){
    perror("socket");
    exit(1);
  }
  //设置成混杂模式
  strcpy(ifr.ifr_name, "ens33");   //enss33网卡

  if(ioctl(sock, SIOCGIFFLAGS, &ifr) == -1){
    perror("ioctl():");
    close(sock);
    exit(1);
  }

  ifr.ifr_flags |= IFF_PROMISC;

  if(ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
    perror("ioctl():");
    close(sock);
    exit(1);
 }
 int frameCnt = 0;

printf("..........................................开始抓包分析........................................\n");
  //无限接受局域网内的报文包  */
while(1){
    //printf("---------------------------------\n");
    n = recvfrom(sock, buffer, MAX_BUFFER_SIZE, 0, NULL,NULL);
    if(n == -1){
      perror("recvfrom()");
      exit(-1);
    }
    else{
      ethead = (unsigned char *)buffer;
      printf("Frame %d : %d bytes one wire, %d bytes captured on interface ens33\n",
              frameCnt, n, n);
              frameCnt++;
      printf("MAC Address:\tSrc:\t%02x:%02x:%02x:%02x:%02x:%02x\t",ethead[0],
    ethead[1],ethead[2],ethead[3],ethead[4],ethead[5]);
    printf("Des:\t%02x:%02x:%02x:%02x:%02x:%02x\n",ethead[6],
  ethead[7],ethead[8],ethead[9],ethead[10],ethead[11]);
      printf("___________________________________________________________________________\n");
      //k++;
      //printf("%u\t%02x\n", (ethead[16]<<8)+ethead[17],ethead[17]);
      printf("Flags:%#2x  %#02x\n", ethead[20],buffer[21]);
      //  close(sock);
      //buffer[12]buffer[13] ==0x0800为ipv4
      if(ethead[12] == 0x08 && ethead[13] == 0x00){
        printf("Ethernet II：Type: %s (%#02x%02x)\n", IPV4STR, ethead[12],ethead[13]);
        printf("___________________________________________________________________________\n");
        printf("IP header:\n");
        printf("Version: %d\n", IPV4);
        printf("Header length:%d(bytes)\n", IPV4_HEADER_LEN);
        printf("Differentiated services field:%#02x\n", ethead[15] );
        printf("Total length:%u\n", (ethead[16]<<8)+ethead[17]);
        printf("Identification:%#02x%02x\n", ethead[18],ethead[19]);
        printf("Flags:%#02x\n", ntohs(ethead[20]));
        printf("\tReserved bit:   %s\n",((ethead[20] & 0x8000) == 0x8000) ? "set\n":"Not set\n");
        printf("\tDont't fragment:%s\n",((ethead[20] & 0x4000) == 0x4000) ? "set\n":"Not set\n");
        printf("\tMore fragments: %s\n",((ethead[20] & 0x2000) == 0x2000) ? "set\n":"Not set\n");
        printf("Fragment offset:%d\n", (ethead[20] & 0x0100) + (ethead[21] & 0xff00));
        printf("Time to live:%u\n", ethead[22]);
        printf("Protocol:");
        processProtolcol(ethead[23]);
        //UDP
        if(ethead[23] == 0x11){
        printf("Header Checksum:%#02x%02x\n", ethead[24],ethead[25]);
        printf("Source Address:%u:%u:%u:%u\n", ethead[26],ethead[27],ethead[28],ethead[29]);
        printf("Destination Address:%u:%u:%u:%u\n", ethead[30],ethead[31],ethead[32],ethead[33]);
        printf("Source port:%u\n", (ethead[34]<<8) + ethead[35]);
        printf("Destination port:%u\n", (ethead[36]<<8) + ethead[37]);
        printf("Length:%u\n", (ethead[38]<<8) +ethead[39]);
        printf("Checksum:%#02x%02x\n", ethead[40],ethead[41]);
          printf("Date:\n\tdata:");
          for(int i = 42 ; i < n ; i++){
            printf("%02x",ethead[i]);
          }
          printf("\n");
          printf("Length:%u\n", n - 42);
          printf("___________________________________________________________________________\n");
        }
        //TCP
        if(ethead[23] == 0x06){
        //  processProtolcol(ethead[23]);
          printf("Header Checksum:%#02x%02x\n", ethead[24],ethead[25]);
          printf("Source Address:%u:%u:%u:%u\n", ethead[26],ethead[27],ethead[28],ethead[29]);
          printf("Destination Address:%u:%u:%u:%u\n", ethead[30],ethead[31],ethead[32],ethead[33]);
          printf("Source port:%u\n", (ethead[34]<<8) + ethead[35]);
          printf("Destination port:%u\n", (ethead[36]<<8) + ethead[37]);
          printf("Sequence number:%u\n",(ethead[38]<<24)+(ethead[39]<<16)+(ethead[40]<<8)+ethead[41]);
          printf("Header length:%u\n", n - 24);
          printf("Flags:%#02x(",ethead[47]);
          if((ethead[46] & 0x1000) == 0x1000)
            printf("syn)\n");
            if(((ethead[46] & 0x1000) == 0x1000)&&(((ethead[46] & 0x4000) == 0x4000)))
              printf("syn,ack)\n");
              if(((ethead[46] & 0x4000) == 0x4000)&&((ethead[47] & 0x1000) == 0x1000))
              printf("fin,ack)\n");
          printf("\tReserved:%s\n",((ethead[46] & 0x9000) == 0x9000)? "set\n":"not set");
          printf("\tNonce:   %s\n",((ethead[46] & 0x8000) == 0x8000)? "set\n":"not set");
          printf("\tCWR:     %s\n",((ethead[46] & 0x7000) == 0x7000)? "set\n":"not set");
          printf("\tECN-Echo:%s\n",((ethead[46] & 0x6000) == 0x6000)? "set\n":"not set");
          printf("\tUrgent:  %s\n",((ethead[46] & 0x5000) == 0x5000)? "set\n":"not set");
          printf("\ACK:      %s\n",((ethead[46] & 0x4000) == 0x4000)? "set\n":"not set");
          printf("\tPush:    %s\n",((ethead[46] & 0x3000) == 0x3000)? "set\n":"not set");
          printf("\tReset:   %s\n",((ethead[46] & 0x2000) == 0x2000)? "set\n":"not set");
          printf("\tSyn:     %s\n",((ethead[46] & 0x1000) == 0x1000)? "set\n":"not set");

          printf("\tFin:     %s\n",((ethead[47] & 0x1000) == 0x1000)? "set\n":"not set");

          printf("Window:%u\n", (ethead[48]<<8)+ethead[49]);

          printf("Checksum:%#02x%02x\n", ethead[50],ethead[51]);

          printf("Urgent:%u\n", (ethead[52]<<8)+ethead[52]);
          printf("___________________________________________________________________________\n");
        }
        //ICMP
        if(ethead[23] == 0x01){
          printf("Type:%u\n", ethead[34]<<8);
          printf("Code:%u\n", ethead[35]<<8);
          printf("Checksum:%#02x%02x\n", ethead[36],ethead[37]);
          printf("Identifer(BE):%u\n", (ethead[38]<<8)+ethead[39]);
          printf("Identifer(LE):%u\n", (ethead[41]<<8)+ethead[40]);
          printf("Date:%u\n",n-50);
          printf("\tdata:\n");
          for(int j = 51 ; j < n ; j++){
            printf("%02x",ethead[j]);
          }
            printf("\n");
        }
        printf("___________________________________________________________________________\n");
        printf("\n");
      }
      //arp
      if(ethead[12] == 0x08 && ethead[13] == 0x06){
        printf("Ethernet II：Type: %s (%#02x%02x)\n", ARPSTR, ethead[12],ethead[13]);
        printf("___________________________________________________________________________\n");
        printf("Address Resolution Protocol\n");
        printf("Hardware type:%u\n", (ethead[14]<<8)+ethead[15]);
        printf("Protocol:     %#02x%02x\n", ethead[16],ethead[17]);
        printf("Hardware size:%u\n", ethead[18]);
        printf("Protocol size:%u\n", ethead[19]);
        printf("Opcode:       %u\n", (ethead[20]<<8)+ethead[21]);
        printf("Sender MAC Address:%02x:%02x:%02x:%02x:%02x:%02x\n",ethead[22],
      ethead[23],ethead[24],ethead[25],ethead[26],ethead[27]);
        printf("Ip Address:%u:%u:%u:%u\n", ethead[28],ethead[29],ethead[30],ethead[31]);
        printf("Target MAC Address:%02x:%02x:%02x:%02x:%02x:%02x\n",ethead[32],
      ethead[33],ethead[34],ethead[35],ethead[36],ethead[37]);
        printf("Target Ip Address:%u:%u:%u:%u\n", ethead[38],ethead[39],ethead[40],ethead[41]);
        printf("___________________________________________________________________________\n");
      }
    }
}
}
void processProtolcol(unsigned char procat){
  switch (procat) {
    case 0x01:
      printf(" ICMP(%u)\n", procat);
      break;
    case 0x02:
      printf(" IGMP(%u)\n", procat);
      break;
      case 0x04:
        printf(" IP(%u)\n", procat);
        break;
        case 0x06:
          printf(" TCP(%u)\n", procat);
          break;
          case 0x11:
            printf(" UDP(%u)\n", procat);
            break;
            default:
              printf("Others(%u)\n",procat);
  }
}
