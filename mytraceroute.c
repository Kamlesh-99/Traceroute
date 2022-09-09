/*
Group 48
Sayantan Saha : 19CS30041
Kamalesh Garnayak : 19CS10074
*/

/*
How to run this code: 
First you have to apply following two commands one by one:
$ gcc mytraceroute_19CS30041.c -o mytraceroute
$ sudo ./mytraceroute www.iitkgp.ac.in
[sudo] password for sayantan: Here you have to enter your password
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>


#define MAX_LEN 6000
#define DEST_PORT 32164


/* Check sum function  */
uint16_t checksum(uint8_t *data, unsigned int size)
{
    int i;
    int sum = 0;
    uint16_t *p = (uint16_t *)data;

    for(i = 0; i < size; i += 2){
        sum += *(p++);
    }

    uint16_t carry = sum >> 16;
    uint16_t tmp = 0x0000ffff & sum;
    uint16_t res = ~(tmp + carry);

    return res;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Error: Invalid parameters!\n");
        printf("Usage: %s <target hostname/IP>\n", argv[0]);
        exit(0);
    }
    socklen_t length;
    int S1, S2;
    struct sockaddr_in src_addr, cli_addr;

    /* Creating two Raw Sockets S1 and S2 */
    S1 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (S1 < 0)
    {
        perror("Socket error for S1");
        exit(0);
    }
    if ((S2 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("Socket error for S2");
        exit(0);
    }
    /* getting the destination IP */
    char ip_address[100];
    
    struct hostent *hpp;
	hpp = gethostbyname(argv[1]);
	struct in_addr ip_addr;
	ip_addr = *(struct in_addr *)hpp->h_addr_list[0];
    strcpy(ip_address, inet_ntoa(ip_addr));

    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(20000);
    src_addr.sin_addr.s_addr = INADDR_ANY; 
    length = sizeof(src_addr);
    /* binding the Sockets */
    if (bind(S1, (struct sockaddr *)&src_addr, length) < 0)
    {
        perror("error in binding");
        exit(0);
    }

    printf("Target IP address : %s \n", ip_address);

    cli_addr.sin_family = AF_INET;
    cli_addr.sin_port = htons(DEST_PORT);
    cli_addr.sin_addr.s_addr = inet_addr(ip_address);

    int enable = 1;
    char payload[52];
    int count = 1;
    fd_set readfd;
    int ttl = 1, timeout = 1;
    if (setsockopt(S1, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) < 0)
    {
        printf("error in setsockopt\n");
        exit(0);
    }    
    clock_t start_time;
    int done = 0;
    for(;;)
    {
        if (ttl <= 16){
            char buf[MAX_LEN];
            struct iphdr *ip = (struct iphdr *)buf;
            struct udphdr *udp = (struct udphdr *)(buf + sizeof(struct iphdr));
            
                /* generating Payload */
            count++;
            for (int k = 0; k < 52; k++)
            {
                payload[k] = rand() % 26 + 'A';
            }
            //memset(buf, 0, MAX_LEN);
            for(int k = 0; k < MAX_LEN; k++){
                buf[k]='\0';
            }

                /* generating UPD and IP header */
            ip->ihl = 5;
            ip->version = 4;
            ip->tos = 0; 
            ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 52; 

                
            udp->source = htons(20000);
            // destination port number
            udp->dest = htons(DEST_PORT);
            udp->len = htons(sizeof(struct udphdr)+52);

            ip->id = htonl(0);
            ip->ttl = ttl;     
            ip->protocol = 17; 
            ip->saddr = 0;     
            ip->daddr = inet_addr(ip_address);

                // calculating the checksum for error checking
            ip->check = checksum((uint8_t *)buf, sizeof(struct iphdr) + sizeof(struct udphdr));

                /* sending the packet */
            strcpy(buf + sizeof(struct iphdr) + sizeof(struct udphdr), payload);
            int l = sendto(S1, buf, ip->tot_len, 0,(struct sockaddr *)&cli_addr, sizeof(cli_addr));
            if (l < 0)
            {
                perror("error in sendto()");                
                exit(0);
            }
            start_time = clock();

            
            /* Waiting on select call */
            FD_ZERO(&readfd);
            FD_SET(S2, &readfd);
            struct timeval tv = {timeout, 0};
            if (select(S2 + 1, &readfd, 0, 0, &tv) == -1)
            {
                perror("error in select call\n");
                exit(0);
            }
            else if (select(S2 + 1, &readfd, 0, 0, &tv)>0)
            {
                // ICMP
                if (FD_ISSET(S2, &readfd))
                {
                    /* Reading the ICMP Message */
                    char msg[100];
                    
                    socklen_t src_len = sizeof(src_addr);
                    clock_t fin_time = clock();
                    if (recvfrom(S2, msg, 100, 0, (struct sockaddr *)&src_addr, &src_len) <= 0)
                    {
                        timeout = 1;
                        
                        
                    }
                    struct iphdr iphdr_new = *((struct iphdr *)msg);
                    int iphdrlen = sizeof(iphdr_new);
                    struct icmphdr hdricmp = *((struct icmphdr *)(msg + iphdrlen));
                    
                    
                    struct in_addr src_ip;
                    src_ip.s_addr = iphdr_new.saddr;
                    if(iphdr_new.protocol == 1) //ICMP
                    {
                        if (hdricmp.type == 11)
                        {
                            //time exceed happened
                            count = 2;
                            timeout = 1;
                            
                            printf("Hop_Count(%d)\t%s\t%.3f ms\n", ttl, inet_ntoa(src_ip), (float)(fin_time - start_time) / CLOCKS_PER_SEC * 1000);
                            ttl++;
                            
                        }
                        else if (hdricmp.type == 3)
                        {
                            // verifying the ip addresses
                            if (iphdr_new.saddr == ip->daddr)
                            {
                                printf("Hop_Count(%d)\t%s\t%.3f ms\n", ttl, inet_ntoa(src_ip), (float)(fin_time - start_time) / CLOCKS_PER_SEC * 1000);                        
                            }
                            done = 1;
                            //return 0;
                        }
                    }
                }
            }
            else
            {
                //timeout happened
                
                timeout = 1;
                if (count > 4)
                {
                    printf("Hop_Count(%d)\t*\t*\t*\t*\n", ttl);
                    count = 2;
                    ttl++;
                }
                
                
            }
            if(done)break;
        }
        else break;
    }
    close(S1);
    close(S2);
    return 0;
}