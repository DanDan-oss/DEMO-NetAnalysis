#include <stdlib.h>
#include <string.h>

#include "dpi.h"


dpi_result* dpi_init(const char* pcap_filename)
{
    char ebuf[PCAP_ERRBUF_SIZE] = {0};  // pcap错误消息存放buffer
    pcap_t* pcap=NULL;
    dpi_result* result = NULL;

    // 打开cap文件
    pcap = pcap_open_offline(pcap_filename, ebuf);
	if(NULL == pcap)
	{
		printf("Error, cap file open fail: %s\n", ebuf);
		return NULL;
	}
    result = malloc(sizeof(dpi_result));
    memset(result, 0, sizeof(dpi_result));
    result->pcap_handle = pcap;
    return result;
}

void dpi_fini(dpi_result* res_ptr)
{
    if( NULL == res_ptr) //传进来的是空指针
        return;

    if(NULL != res_ptr->pcap_handle)
        pcap_close(res_ptr->pcap_handle);
    free(res_ptr);
    res_ptr = NULL;
    return;
}

void dpi_loop(dpi_result* res_ptr)
{
    //typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
    pcap_loop(res_ptr->pcap_handle, 0, &pcap_callback, (u_char*)res_ptr);
    printf("数据处理: 以太网包数量有%d\n", res_ptr->ether_count);
	printf("数据处理: IP包数量有%d\n", res_ptr->ip_count);
    return;
}

struct aptest
{
    struct _dpi_eth_head eth;
    struct _dpi_ip_head ip;
};

void pcap_callback(u_char* user, const struct pcap_pkthdr* h,  const u_char* bytes)
{
   dpi_result* res_ptr= (dpi_result*)user;
   dpi_pkt pkt = {0};
   u_int32_t eth_type=0;
// 以太网包解析, 处理的每一个包都是以太网包
    ++res_ptr->ether_count;
    eth_type = analysis_ether( &pkt, (void*)bytes, h->caplen, res_ptr);
   return;
}

u_int32_t analysis_ether(dpi_pkt* pkt_ptr, void* ether_buffer,  uint32_t ether_len, 
            dpi_result* res_ptr)
{
    pkt_ptr->eth_head_ptr = (dpi_eth_head*)ether_buffer;
    pkt_ptr->ether_len =  ether_len;

    /*
    // 以太网帧长度 = 网络层长度 + 以太网头长度
    // 以太网帧长度除去CRC 4字节最低60,如果IP报文过短,剩余0填充.
    // 以太网帧长度除去CRC 4字节最大1514.

    // TODO: 验证-->有部分以太网帧向上取整到60了,有部分没有取整60只有54
    uint16_t ether_length = ntohs(*(uint16_t*) ((u_int8_t*)ether_buffer +14+2)) +14;
    if(1514 < ether_length)
        ether_length = 1514;
    // else if(60 >ether_length)
    //     ether_length = 60;

    printf("以太网帧 type:%.4x   WirShark解析长度:%d   计算长度:%d\n", 
            ntohs(*(u_int16_t*) ((u_int8_t*)ether_buffer+12)), ether_len, ether_length);
    return 0;
    */
   
    // TODO: 网络字节序转主机字节序 (mac地址6字节)
    // 网络层类型 IP=0x0800  ARP=0x0806 RARP=0x8035
    u_int16_t type = ntohs(*(u_int16_t*) ((u_int8_t*)ether_buffer+12));
    u_int8_t dhost[6] = {0};
    u_int8_t shost[6] = {0};
    
    // 目的地mac地址 6个字节
    *(uint32_t*) dhost = ntohl(*(uint32_t*) ((u_int8_t*)ether_buffer+0));
    *(uint16_t*)(dhost+4) = ntohs(*(uint16_t*) ((u_int8_t*)ether_buffer+4));
    // 源地址mac地址
    *(uint32_t*) shost = ntohl(*(uint32_t*) ((u_int8_t*)ether_buffer+6));
    *(uint16_t*)(shost+4) = ntohs(*(uint16_t*) ((u_int8_t*)ether_buffer+10));

    printf("Type:%.4x Length:%d  DestMac:%.8x%.4x SrcMac:%.8x%.4x\n", type, pkt_ptr->ether_len, 
        *(u_int32_t*)dhost, *(uint16_t*)(dhost+4) , *(uint32_t*)shost, *(uint16_t*)(shost+4));
    
    
    // IP报文
    if(0x0800 == type)
    {
        if(NULL != res_ptr)
            ++res_ptr->ip_count;
        // IP报文长度 = 以太网长度 - 以太网头长度(14字节)
        pkt_ptr->ip_len = pkt_ptr->ether_len - 14;
        // IP头地址 = 以太网头地址 + 以太网头长度
        pkt_ptr->ip_head_ptr =(dpi_ip_head*) ((u_int8_t*)ether_buffer + 14);
        analysis_ip(pkt_ptr, pkt_ptr->ip_head_ptr, pkt_ptr->ip_len, res_ptr);
    }
    return pkt_ptr->eth_head_ptr->eth_type;
}

u_int32_t analysis_ip(dpi_pkt* pkt_ptr, void* ip_buffer,  uint32_t ip_len,  dpi_result* res_ptr)
{
    pkt_ptr->ip_head_ptr = ip_buffer;
    //pkt_ptr->ip_len = ip_len;
    pkt_ptr->ip_len = ntohs(*(uint16_t*) ((u_int8_t*)ip_buffer +2));

    // 网络字节序转主机字节序 之后打印
    // IP版本号, IPV4，IPV6
    u_int8_t ip_version = *(u_int8_t*)ip_buffer>>4;
    // IP头长度,一般20字节=值x4
    u_int8_t ip_head_len=(*(u_int8_t*)ip_buffer &0x0f) *4;
    //IP报文总长度(报头+数据)
    uint16_t ipdate_len = ntohs(*(uint16_t*) ((u_int8_t*)ip_buffer +2));
    // IP报文ID
    uint16_t ipdate_id = ntohs(*(uint16_t*) ((u_int8_t*)ip_buffer +4));
    // 网络层协议, ICMP：1，TCP：6，UDP：17
    uint8_t proto = *(uint8_t*)((u_int8_t*)ip_buffer +9);
    // IP地址
    u_int8_t src_addr[20] = {0};
    u_int8_t des_addr[20] = {0};

    if(4 != ip_version)
    {
        printf("error: IP Version not IPV4\n");
        return 0;
    }    

    inet_ntop(AF_INET, (const u_int8_t*)ip_buffer +12, src_addr, sizeof(src_addr));
    inet_ntop(AF_INET, (const u_int8_t*)ip_buffer +16, des_addr, sizeof(des_addr));

    printf("    ipVer:%x ipHeadLen:%d ipLen:%d ipID:%.4x proto:%d ipSrc:%s ipDest:%s \n", 
       ip_version, ip_head_len, ipdate_len, ipdate_id, proto, src_addr, des_addr);
    

    return pkt_ptr->ip_head_ptr->protocol;
}