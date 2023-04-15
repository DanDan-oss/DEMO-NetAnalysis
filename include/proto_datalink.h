#ifndef _PROTO_DATALINK_H
#define _PROTO_DATALINK_H 1

/* ============================
物理层: ...
数据链路层: 以太网、局域网
============================ */
#include <netinet/in.h>

// 以太网头
typedef struct _dpi_eth_head
{
    uint8_t dstmac[6];  // 目标mac地址
    uint8_t srcmac[6];  // 源mac地址
    uint16_t eth_type;  // 网络层包类型
}dpi_eth_head, *dpi_eth_head_ptr;

/* 解析处理以太网包报文
@pkt_ptr: 存放解析数据的地址
@ether_buffer: 报文数据
@ether_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
    返回值: 网络层报文类型
*/
u_int32_t analysis_ether(void* pkt_ptr, void* ether_buffer,  uint32_t ether_len,  void* res_ptr);

#endif