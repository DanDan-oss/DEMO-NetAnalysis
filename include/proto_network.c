#include "dpi.h"
#include "proto_network.h"
#include "proto_transport.h"

u_int32_t analysis_ip(void* pkt_ptr, void* ip_buffer,  uint32_t ip_len,  void* res_ptr)
{
    if(NULL == ip_buffer)
    {
        printf("Error: ip_buffer is null\n");
        return 0;
    }
    if(res_ptr)
        ++((dpi_result*)res_ptr)->ip_count;

    dpi_ip_head* ip_head_ptr= ((dpi_pkt*)pkt_ptr)->ip_head_ptr = ip_buffer;
    ((dpi_pkt*)pkt_ptr)->ip_len = ip_len;

    // 网络字节序转主机字节序 之后打印
    // IP版本号, IPV4，IPV6
    u_int8_t ip_version = ip_head_ptr->ip_version;
    // IP头长度,一般20字节=值x4
    u_int8_t ip_head_len= ip_head_ptr->ip_headlen *4;
    //IP报文总长度(报头+数据)
    uint16_t ipdate_len = ntohs(ip_head_ptr->ip_tot_len);
    // IP报文ID
    uint16_t ipdate_id = ntohs(ip_head_ptr->ip_id);
    // 网络层协议, ICMP：1，TCP：6，UDP：17
    uint8_t proto = ip_head_ptr->ip_proto;
    // 分片编号
    uint8_t ip_fragnum = ip_head_ptr->ip_frag_num;
    // IP地址
    u_int8_t src_addr[20] = {0};
    u_int8_t des_addr[20] = {0};

    if(4 != ip_version)
    {
        printf("error: IP Version not IPV4\n");
        return 0;
    }

    inet_ntop(AF_INET, (const u_int8_t*)&ip_head_ptr->ip_saddr, src_addr, sizeof(src_addr));
    inet_ntop(AF_INET, (const u_int8_t*)&ip_head_ptr->ip_daddr, des_addr, sizeof(des_addr));

    //printf("    ipVer:%x ipHeadLen:%d ipLen:%d ipID:%.4x proto:%d ipSrc:%s ipDest:%s \n", \
       ip_version, ip_head_len, ipdate_len, ipdate_id, proto, src_addr, des_addr);

    
    switch (proto)
    {
    case IPPROTO_ICMP:    //ICMP：1
        if(res_ptr)
            ++((dpi_result*)res_ptr)->icpm_count;
        break;

    case IPPROTO_TCP:    //TCP：6

        // TCP报文长度 = IP长度 - IP头长度(20字节)
        u_int32_t tcp_len = ip_len - ip_head_len;
        // TCP头地址 = IP地址 + IP头长度
        dpi_tcp_head* tcp_buffer = ( dpi_tcp_head*)((u_int8_t*)ip_head_ptr + ip_head_len);
        analysis_tcp(pkt_ptr, tcp_buffer, tcp_len, res_ptr);
        break;

    case IPPROTO_UDP:   // UDP：17
    {
        u_int32_t udp_len = ip_len - ip_head_len;
        dpi_udp_head* udp_buffer = (dpi_tcp_head*)((u_int8_t*)ip_head_ptr + ip_head_len);
        analysis_udp(pkt_ptr, udp_buffer, udp_len, res_ptr);
        break;
    }

    default:    // 其他协议
        break;
    }

    return proto;
}