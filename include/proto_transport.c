#include "dpi.h"
#include "proto_application.h"
#include "proto_transport.h"


u_int32_t analysis_tcp(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr)
{
    dpi_pkt* dpi_pkt_ptr = (dpi_pkt*)pkt_ptr;

    if(NULL == tcp_buffer || tcp_len< 20)
    {
        printf("Error: tcp_buffer is null\n");
        return 0;
    }
    if(res_ptr)
        ++((dpi_result*)res_ptr)->tcp_count;

    if (dpi_pkt_ptr)
    {
        dpi_pkt_ptr->tcp_head_ptr = tcp_buffer;
        dpi_pkt_ptr->ip_len = tcp_len;
    }
    
    dpi_tcp_head* tcp_head_ptr = tcp_buffer;
    uint16_t sport = htons(tcp_head_ptr->tcp_sport);
    uint16_t dport = htons(tcp_head_ptr->tcp_dport);
    uint32_t seq = htonl(tcp_head_ptr->tcp_seq);
    uint32_t ack = htonl(tcp_head_ptr->tcp_ack);
    uint16_t tcp_hand_len = tcp_head_ptr->tcp_head_Len * 4;
    uint16_t check = htons(tcp_head_ptr->tcp_check);

    //printf("        Sport:%d Dport:%d Seq:%ld Ack:%ld \n", tcp_hand_len, sport, dport, seq, ack);

    // 应用层长度 = tcp总长度- tcp头长度
    uint16_t app_len = tcp_len - tcp_hand_len;
    // 应用层协议起始地址 = tcp起始地址+tcp头长度
    uint8_t* app_buffer = (uint8_t*)tcp_buffer + tcp_hand_len;

    // TODO: 循环调用TCP应用层支持的协议解析函数
    for (int i = 0; i < PROTOCOL_TCP_MAX; ++i)
        if (0 == protocl_analyze_tcp_funcs[i](dpi_pkt_ptr, app_buffer, app_len, res_ptr))
            break;


    return seq;
}

u_int32_t analysis_udp(void* pkt_ptr, void* udp_buffer,  uint32_t udp_len,  void* res_ptr)
{
    dpi_pkt* dpi_pkt_ptr = (dpi_pkt*)pkt_ptr;

    if(NULL == udp_buffer || udp_len < 8)
    {
        printf("Error: udp_buffer is null\n");
        return 0;
    }
    if (res_ptr)
        ++((dpi_result *)res_ptr)->udp_count;
    
    if (dpi_pkt_ptr)
    {
        dpi_pkt_ptr->tcp_head_ptr = udp_buffer;
        dpi_pkt_ptr->ip_len = udp_len;
    }

    dpi_udp_head* udp_head_ptr = udp_buffer;
    uint16_t sport = htons(udp_head_ptr->source);
    uint16_t dport = htons(udp_head_ptr->dest);
    uint16_t udpsize = htons(udp_head_ptr->len);

    // 应用层长度 = udp总长度- udp头长度
    uint16_t app_len = udpsize - 8;
    // 应用层协议起始地址 = udp起始地址+udp头长度
    uint8_t *app_buffer = (uint8_t *)udp_buffer + 8;

    //printf("    udp: sport:%d dport:%d udplen:%d\n", sport, dport, udpsize);
    // TODO: 循环调用UDP应用层支持的协议解析函数
    for (int i = 0; i < PROTOCOL_UDP_MAX; ++i)
        if (0 == protocl_analyze_udp_funcs[i](pkt_ptr, app_buffer, app_len, res_ptr))
            break;


    return 0;
}