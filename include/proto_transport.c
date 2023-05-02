#include "dpi.h"
#include "proto_application.h"
#include "proto_transport.h"


u_int32_t analysis_tcp(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr)
{
    if(NULL == tcp_buffer)
    {
        printf("Error: tcp_buffer is null\n");
        return 0;
    }
    if(res_ptr)
        ++((dpi_result*)res_ptr)->tcp_count;

    dpi_tcp_head* tcp_head_ptr= ((dpi_pkt*)pkt_ptr)->tcp_head_ptr = tcp_buffer;
    ((dpi_pkt*)pkt_ptr)->ip_len = tcp_len;

    uint16_t sport = htons(tcp_head_ptr->tcp_sport);
    uint16_t dport = htons(tcp_head_ptr->tcp_dport);
    uint32_t seq = htonl(tcp_head_ptr->tcp_seq);
    uint32_t ack = htonl(tcp_head_ptr->tcp_ack);
    uint16_t tcp_hand_len = tcp_head_ptr->tcp_head_Len * 4;
    uint16_t check = htons(tcp_head_ptr->tcp_check);

    printf("        Sport:%d Dport:%d Seq:%ld Ack:%ld \n", tcp_hand_len, sport, dport, seq, ack);

    // 应用层长度 = tcp总长度- tcp头长度
    uint16_t app_len = tcp_len - tcp_hand_len;
    // 应用层协议起始地址 = tcp起始地址+tcp头长度
    uint8_t* app_buffer = (uint8_t*)tcp_buffer + tcp_hand_len;

    // TODO: 循环调用TCP应用层支持的协议解析函数
    for(int i=0 ; i<PROTOCOL_TCP_MAX; ++i)
        if(0 == protocl_analyze_funcs[i](pkt_ptr, app_buffer, app_len, res_ptr))
            break;
    return seq;
}