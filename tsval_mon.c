#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <signal.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/swab.h>
#include <stdlib.h>
#include <time.h>

//list for tsvals
struct TListTSVals
{
    unsigned ts_val;
    struct TListTSVals *next;
};

//list for ip<->[tsvals]
struct TListIp
{
    unsigned ip;
    struct TListIp *next;
    struct TListTSVals *vals;
};

pcap_t *handle;
struct TListIp *list;
uint32_t period;
time_t last_time;
char *fname;

void dump_log(time_t now)
{
    printf("Dumping\n");
    FILE *f=fopen(fname,"a");
    if(f)
    {
        struct TListIp *last_l=NULL;
        for(struct TListIp *l=list;l;l=l->next)
        {
            u_char *ip=(u_char*)&l->ip;
            printf("%d.%d.%d.%d %lu %lu",ip[0],ip[1],ip[2],ip[3],last_time,now);
            fprintf(f,"%d.%d.%d.%d %lu %lu",ip[0],ip[1],ip[2],ip[3],last_time,now);
            struct TListTSVals *last_ls=NULL;
            for(struct TListTSVals *ls=l->vals;ls;ls=ls->next)
            {
                if(last_ls)free(last_ls);
                printf(" %u",ls->ts_val);
                fprintf(f," %u",ls->ts_val);
                last_ls=ls;
            }
            if(last_ls)free(last_ls);
            printf("\n");
            fprintf(f,"\n");
            if(last_l)free(last_l);
            last_l=l;
        }
        list=NULL;
        if(last_l)free(last_l);
        fclose(f);
    }
    else
        printf("Error in opening file %s\n",fname);
}

void my_halt(int signal)
{
    pcap_close(handle);
    dump_log(time(NULL));
    printf("\nStopping\n");
}

void add_to_list(unsigned ip, unsigned tsval)
{
    for(struct TListIp *l=list;l;l=l->next)
    {
        if(l->ip==ip)
        {
            for(struct TListTSVals *ls=l->vals;ls;ls=ls->next)
                if(ls->ts_val==tsval)
                    return;//found tsval with this ip
            struct TListTSVals *ls=(struct TListTSVals *)malloc(sizeof(struct TListTSVals));
            ls->ts_val=tsval;
            ls->next=l->vals;
            l->vals=ls;
            return;//add tsval to ip
        }
    }
    //not found ip, add new
    struct TListIp *l=(struct TListIp *)malloc(sizeof(struct TListIp));
    l->ip=ip;
    l->next=list;
    struct TListTSVals *ls=(struct TListTSVals *)malloc(sizeof(struct TListTSVals));
    ls->ts_val=tsval;
    ls->next=NULL;
    l->vals=ls;
    list=l;
}

//pcap callback
void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet)
{
    struct ether_header *ethh=(struct ether_header*)&packet[0];
    struct iphdr *iph=(struct iphdr*)&packet[sizeof(struct ether_header)];
    u_char *pck=(u_char*)&packet[sizeof(struct ether_header)+sizeof(struct iphdr)+sizeof(struct tcphdr)];//options offset
    time_t now=time(NULL);
    if((last_time+period-1)<=now)
    {
        dump_log(last_time+period-1);
        last_time=now;
    }
    if( (ntohs(ethh->ether_type) == ETHERTYPE_IP)
            && (iph->protocol == IPPROTO_TCP) )
    {
        struct tcphdr *tcp_header=(struct tcphdr *)((uint32_t*)iph+iph->ihl);
        uint32_t cnt=0;

        //iterate through opts
        if(tcp_header->doff>5)//5-minimal header size w/o opts
        while(cnt<(tcp_header->doff*4-sizeof(struct tcphdr)))
        {
            if(pck[cnt]==1)
                cnt++;
            else if(pck[cnt]==0)
                break;
            else if(pck[cnt]==8)
            {
                add_to_list(iph->saddr,__fswab32(*(uint32_t*)&pck[cnt+2]));
                //printf("%lu\n",time(NULL));
                cnt+=pck[cnt+1];
            }
            else //if(pck[cnt]!=0)
                cnt+=pck[cnt+1];
            if(cnt>=40)//theoretical maximum size of opts
                break;
        }
    }
}

int main(int argc, char **argv)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device = "enp0s3";
    int snapshot_len = 1028;//enough for headers
    int promiscuous = 0;
    int timeout = 1000;
    struct sigaction sigIntHandler;

    if((argc!=6))
    {
        printf("Usage:%s -i <interface> -p <period> /path/to/log\n",argv[0]);
        return 0;
    }
    else
    {
        for(int cnt=1;cnt<argc;cnt++)
        {
            if((argv[cnt][0]=='-') && (argv[cnt][1]=='i') && (argv[cnt][2]=='\0'))
            {
                cnt++;
                device=argv[cnt];
            }
            else if((argv[cnt][0]=='-') && (argv[cnt][1]=='p') && (argv[cnt][2]=='\0'))
            {
                cnt++;
                period=atol(argv[cnt]);
            }
            else
                fname=argv[cnt];
        }
    }
    
    //handle control+c
    sigIntHandler.sa_handler=my_halt;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    list=NULL;

    handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buffer);

    if(handle)
    {
        printf("Start monitoring on %s to %s every %d s.\nPress ctrl+C to stop.\n",device,fname,period);
        last_time=time(NULL);
        pcap_loop(handle, 0, my_packet_handler, NULL);
    }
    else
        printf("%s\n",error_buffer);
    return 0;
}
