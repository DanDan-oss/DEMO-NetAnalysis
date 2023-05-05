#ifndef _PROTO_APPLICATION_H
#define _PROTO_APPLICATION_H 1

#include <netinet/in.h>

// 当前HTTP下可以解析的应用层协议 PROTO_TCP_STRING和 _TCP_PROTOCOL必须一一对应
#define PROTO_TCP_STRING \
    "SSH",    \
    "HTTP",  \
    "FTP",
    
typedef enum _TCP_PROTOCOL
{
    SSH=0,
    HTTP=1,
    FTP=2,
    PROTOCOL_TCP_MAX
}TCP_PROTOCOL;

// TCP应用层协议函数类型定义
typedef u_int32_t (*protocl_tcp_analyze_func_t)(void*, void*,  uint32_t,  void*);
// TCP下的应用层协议函数数组定义(由于多个源文件导入,会重复定义,添加extern导入有定义的源文件的)
extern protocl_tcp_analyze_func_t protocl_analyze_tcp_funcs[PROTOCOL_TCP_MAX];
// TCP下的应用层协议排列
extern const char* g_protocl_tcp_string[PROTOCOL_TCP_MAX];

/* 处理TCP报文协议
@pkt_ptr:
@tcp_buffer: tcp报文缓冲区
@tcp_len: TCP报文长度
@res_ptr: tcp报文计数,可为NULL
@return
    0 处理成功
    1 处理失败
*/ 
u_int32_t analysis_http(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);
u_int32_t analysis_ssh(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);
u_int32_t analysis_ftp(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);



/* ================= UDP ==============*/
#define PROTO_UDP_STRING \
    "TFTP",    \
    "NTP",

typedef enum _UDP_PROTOCOL
{
    TFTP=0,
    NTP=1,
    PROTOCOL_UDP_MAX
}UDP_PROTOCOL;
typedef u_int32_t (*protocl_udp_analyze_func_t)(void* pkt_ptr, void* udp_buffer,  uint32_t udp_len,  void* res_ptr);

extern protocl_udp_analyze_func_t protocl_analyze_udp_funcs[PROTOCOL_UDP_MAX];
extern const char* g_protocl_udp_string[PROTOCOL_UDP_MAX];


/* 处理UDP报文协议
@pkt_ptr:
@tcp_buffer: tcp报文缓冲区
@tcp_len: TCP报文长度
@res_ptr: tcp报文计数,可为NULL
@return
    0 处理成功
    1 处理失败
*/ 
u_int32_t analysis_tftp(void* pkt_ptr, void* udp_buffer,  uint32_t udp_len,  void* res_ptr);
u_int32_t analysis_ntp(void* pkt_ptr, void* udp_buffer,  uint32_t udp_len,  void* res_ptr);
#endif