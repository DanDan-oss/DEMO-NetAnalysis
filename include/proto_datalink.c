#include "dpi.h"
#include "proto_datalink.h"
#include "proto_network.h"


u_int32_t analysis_ether(void* pkt_ptr, void* ether_buffer,  uint32_t ether_len, void* res_ptr)
{
    if(NULL == ether_buffer)
    {
        printf("ERROR: ether_buffer is NULL\n");
        return  0;
    }
    if(!res_ptr)
        ++((dpi_result*)res_ptr)->ether_count;

    dpi_eth_head* eth_head_ptr = ((dpi_pkt*)pkt_ptr)->eth_head_ptr = (dpi_eth_head*)ether_buffer;
    ((dpi_pkt*)pkt_ptr)->ether_len =  ether_len;
    /*
    // 以太网帧长度 = 网络层长度 + 以太网头长度
    // 以太网帧长度除去CRC 4字节最低60,如果IP报文过短,剩余0填充.
    // 以太网帧长度除去CRC 4字节最大1514.

    // TODO: 验证-->有部分以太网帧向上取整到60了,有部分没有取整60只有54
    uint16_t ether_length = ntohs(*(uint16_t*) ((u_int8_t*)ether_buffer +14+2)) +14;
    if(1514 < ether_length)
        ether_length = 1514;
     else if(60 >ether_length)
         ether_length = 60;

    printf("以太网帧 type:%.4x   WirShark解析长度:%d   计算长度:%d\n", 
            ntohs(*(u_int16_t*) ((u_int8_t*)ether_buffer+12)), ether_len, ether_length);
    return 0;
    */
   
    // TODO: 网络字节序转主机字节序 (mac地址6字节)
    // 网络层类型 IP=0x0800  ARP=0x0806 RARP=0x8035
    u_int16_t type = ntohs(eth_head_ptr->eth_type);
    u_int8_t dhost[6] = {0};
    u_int8_t shost[6] = {0};
    
    // 目的地mac地址 6个字节
    *(uint32_t*) dhost = ntohl(*(uint32_t*) ((u_int8_t*)ether_buffer+0));
    *(uint16_t*)(dhost+4) = ntohs(*(uint16_t*) ((u_int8_t*)ether_buffer+4));
    // 源地址mac地址
    *(uint32_t*) shost = ntohl(*(uint32_t*) ((u_int8_t*)ether_buffer+6));
    *(uint16_t*)(shost+4) = ntohs(*(uint16_t*) ((u_int8_t*)ether_buffer+10));

    //printf("Type:%.4x Length:%d  DestMac:%.8x%.4x SrcMac:%.8x%.4x\n", type, ether_len, \
        *(u_int32_t*)dhost, *(uint16_t*)(dhost+4) , *(uint32_t*)shost, *(uint16_t*)(shost+4));
    #include <netinet/ip.h>
        struct iphdr i = {0};
    // IP报文
    if(ETH_P_IP  == type)
    {
        // IP报文长度 = 以太网长度 - 以太网头长度(14字节)
        u_int32_t ip_len = ether_len - sizeof(dpi_eth_head);
        // IP头地址 = 以太网头地址 + 以太网头长度
        void* ip_buffer  =(dpi_ip_head*) ((u_int8_t*)eth_head_ptr + sizeof(dpi_eth_head));
        analysis_ip(pkt_ptr, ip_buffer, ip_len, res_ptr);
    }

    
    return eth_head_ptr->eth_type;
}