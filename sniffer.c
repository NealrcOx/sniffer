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

  int sock, n;
  char buffer[65536];

  struct ifreq ifr;

  sock = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_IP)); //ETH_P_IP就会收不到自己发出去的包
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

  //无限接受局域网内的报文包  */
while(1){
    printf("---------------------------------\n");
    n = recvfrom(sock, buffer, 65536, 0, NULL,NULL);
  }
}
