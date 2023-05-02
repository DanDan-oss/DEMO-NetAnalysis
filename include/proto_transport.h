#ifndef _PROTO_TRANSPORT_H
#define _PROTO_TRANSPORT_H 1

/* ============================
传输层: TCP、UDP
============================ */
#include <netinet/in.h>

// tcp头
typedef struct _dpi_tcp_head
{
	uint16_t tcp_sport;     // 源端口
	uint16_t tcp_dport;     // 目标端口
    uint32_t tcp_seq;
    uint32_t tcp_ack;

    //uint16_t flags;     // 4位头首部长度;  6位保留位; 6位标志位(URG、ACK、PSH、PST、SYN、FIN);
#if __BYTE_ORDER == __LITTLE_ENDIAN	//大端
	uint16_t res1:4;    // 6位保留位中的前4位
	uint16_t tcp_head_Len : 4;    // 4位头首部长度
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;    // 6位保留位中的后2位
#elif __BYTE_ORDER == __BIG_ENDIAN	// 小端
	uint16_t tcp_head_Len : 4;    // 4位头首部长度
	uint16_t res1:4;    // 6位保留位中的前4位
	uint16_t res2:2;    // 6位保留位中的后2位
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#endif

	uint16_t tcp_window;    // 16位滑动窗口大小
	uint16_t tcp_check;     // 16位TCP头校验和
	uint16_t tcp_urg_ptr;   // 16位紧急指针
}dpi_tcp_head, *dpi_tcp_head_ptr;

/* 解析处理tcp包报文
@pkt_ptr: 存放解析数据的地址
@tcp_buffer: 报文数据
@tcp_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
@return: 
	解析失败 0
	成功 网络层报文类型
*/
u_int32_t analysis_tcp(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);

#endif