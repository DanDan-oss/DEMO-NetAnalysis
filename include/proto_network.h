#ifndef _PROTO_NETWORK_H
#define _PROTO_NETWORK_H 1

/* ============================
网络层: IP、ICPM、ARP、RARP、AKP、UUCP
============================ */
#include <netinet/in.h>

// IP头
typedef struct _dpi_ip_head
{
#if __BYTE_ORDER == __LITTLE_ENDIAN	//大端
    uint8_t ip_headlen : 4;  //版本 IPV4，IPV6
    uint8_t ip_version : 4;  //IP头长度,,一般值是5,一个位代表4个字节的长度.首部大小5*4=20字节
#elif __BYTE_ORDER == __BIG_ENDIAN	// 小端
    uint8_t ip_version:4; 
    uint8_t ip_headlen:4; 
#endif

    uint8_t ip_tos;        //服务类型,一般没有使用，详细参考RFC
    uint16_t ip_tot_len;  //header＋数据 总长度
    uint16_t ip_id;       //IP 报文的唯一id，分片报文的id 相同，便于进行重组

    //uint16_t ip_frag_off; //分片编号(标明是否分片)+分片偏移(偏移值/8)
    
#if __BYTE_ORDER == __LITTLE_ENDIAN	//大端
    uint16_t ip_frag_off_1 : 5;    //偏移值前5位
    uint16_t ip_frag_num : 3;     //分片编号
    uint16_t ip_frag_off_2 : 8;    //偏移值后8位
#elif __BYTE_ORDER == __BIG_ENDIAN	// 小端
    uint16_t ip_frag_num : 3;
    uint16_t ip_frag_off_1 : 5;
    uint16_t ip_frag_off_2 : 8; 
#endif

    uint8_t ip_ttl;       //路由器的跳转数
    uint8_t ip_proto;  //传输层协议, ICMP：1，TCP：6，UDP：17
    uint16_t ip_check;    //IP header校验和,如果接收端收到报文进行计算如果校验和错误,直接丢弃。
    uint32_t ip_saddr;    //源IP地址
    uint32_t ip_daddr;    //目的IP地址
}dpi_ip_head, *dpi_ip_head_ptr;


/* 解析处理IP包报文
@pkt_ptr: 存放解析数据的地址
@ip_buffer: 报文数据
@ip_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
@return: 
	解析失败 0
	成功 网络层报文类型
*/
u_int32_t analysis_ip(void* pkt_ptr, void* ip_buffer,  uint32_t ip_len,  void* res_ptr);




#endif