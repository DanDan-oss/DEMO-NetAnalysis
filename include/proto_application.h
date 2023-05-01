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
extern protocl_tcp_analyze_func_t protocl_analyze_funcs[PROTOCOL_TCP_MAX];
// TCP下的应用层协议排列
extern const char* protocl_tcp_string[PROTOCOL_TCP_MAX];

u_int32_t analysis_http(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);
u_int32_t analysis_ssh(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);
u_int32_t analysis_ftp(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);



#endif