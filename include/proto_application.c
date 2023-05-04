#include "dpi.h"
#include "proto_application.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TCP协议数组名
const char* g_protocl_tcp_string[PROTOCOL_TCP_MAX]=
{
    PROTO_TCP_STRING
};

// TCP应用层协议解析函数数组
protocl_tcp_analyze_func_t protocl_analyze_tcp_funcs[PROTOCOL_TCP_MAX] =
{
    analysis_http,
    analysis_ssh,
    analysis_ftp
};

// http报文类型
#define HTTP_VERSION_1_0 "HTTP/1.0"
#define HTTP_VERSION_1_1 "HTTP/1.1"
#define CRLF "\r\n"

enum _HTTP_REQUEST_MOTHOD
{
    GET = 0,
    HEAD,
    POST,
    OPTIONS,
    PUT,
    DELETE,
    TRACE,
    CONNECT,
    HTTP_REQUEST_MAX
}HTTP_REQUEST_MOTHOD;

const char* g_http_request_mothod_strings[HTTP_REQUEST_MAX]=
{
    "GET",
    "HEAD",
    "POST",
    "OPTIONS",
    "PUT",
    "DELETE",
    "TRACE",
    "CONNECT",
};

/* ========  UDP =======*/
const char* g_protocl_udp_string[PROTOCOL_UDP_MAX]=
{
    PROTO_UDP_STRING
};
protocl_udp_analyze_func_t protocl_analyze_udp_funcs[PROTOCOL_UDP_MAX] = 
{
    analysis_tftp,
    analysis_ntp
};

/* ========  TFTP =======*/
#define TFTP_RWRQ_MINSIZE (9)   // Opcode:2字节 + Filename:至少1字节 + 1字节0 + Mode:至少4+ 1字节0

typedef enum _TFTP_RWRQ_MODE
{
    NETASCII = 0,
    MAIL,
    OCTET,
    TFTP_RWRQ_MODE_MAX
}TFTP_RWRQ_MODE;

const char* g_tftp_rwrq_mode_strings[TFTP_RWRQ_MODE_MAX]=
{
    "netascii",
    "mail",
    "octet"
};


/* 处理HTTP报文协议
    @return
        0 处理成功
        1 处理失败
*/ 
u_int32_t analysis_http(void* pkt_ptr, void* app_buffer,  uint32_t tcp_len,  void* res_ptr)
{
    dpi_connection_t ip = {0};

    if( NULL == app_buffer)
        return 1;

    // 如果报文长度 < 最长的请求方法长度 + http版本长度 + 空格 + CRLF(\r\n换行),说明它不是http
    if(tcp_len < strlen(g_http_request_mothod_strings[CONNECT]) + strlen(HTTP_VERSION_1_0) + strlen(" ") + strlen(CRLF))
        return 1;

    // TODO: 匹配请求消息 GET <url> HTTP1.1\r\n
    for(int i=0; i<HTTP_REQUEST_MAX; ++i)
    {
        size_t str_len = strlen(g_http_request_mothod_strings[i]);
        if(0 != memcmp(app_buffer, g_http_request_mothod_strings[i], str_len))
            continue;

        // 匹配到请求头方法后(正常情况不怕没有空格),从请求头方法开始遍历查找空格找到HTTP版本的位置
        const char* ptr = (const char*)app_buffer+str_len+1;
        for(; *ptr != ' '; ptr++);
        ptr++;
        // 匹配 HTTP版本字符串
        if(0 == memcmp(ptr, HTTP_VERSION_1_0, strlen(HTTP_VERSION_1_0)) || \
            0 == memcmp(ptr, HTTP_VERSION_1_1, strlen(HTTP_VERSION_1_1)))
        {
            goto ANALYSIS_HTTP_SUCCESS_ADDLIST;
        }
            
    }

    // TODO: 匹配应答消息 HTTP1.1 200 OK
    if (0 == memcmp(app_buffer, HTTP_VERSION_1_0, strlen(HTTP_VERSION_1_0)) ||
        0 == memcmp(app_buffer, HTTP_VERSION_1_1, strlen(HTTP_VERSION_1_1)))
    {
        goto ANALYSIS_HTTP_SUCCESS_ADDLIST;
    }

return 1;
// 匹配HTTP成功

ANALYSIS_HTTP_SUCCESS_ADDLIST:
    if (NULL != ((dpi_pkt *)pkt_ptr)->ip_head_ptr && NULL != ((dpi_pkt *)pkt_ptr)->tcp_head_ptr)
    {
        ip.ipv4.src_port = ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_sport;
        ip.ipv4.dst_Port = ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_dport;
        ip.ipv4.dst_ip = ((dpi_pkt *)pkt_ptr)->ip_head_ptr->ip_daddr;
        ip.ipv4.src_ip = ((dpi_pkt *)pkt_ptr)->ip_head_ptr->ip_saddr;
    }
    if (NULL == find_connect_ipproto_list(&ip, HTTP))
        add_connect_ipproto_list(&ip, HTTP);

ANALYSIS_HTTP_SUCCESS:
    if (NULL != pkt_ptr)
    {
        ((dpi_pkt *)pkt_ptr)->http_head_ptr = app_buffer;
        ((dpi_pkt *)pkt_ptr)->http_len = tcp_len;
    }
    if (NULL != res_ptr)
        ++((dpi_result *)res_ptr)->tcp_proto_count[HTTP];
    return 0;

}

// 处理SSH报文协议
u_int32_t analysis_ssh(void* pkt_ptr, void* app_buffer,  uint32_t tcp_len,  void* res_ptr)
{
    dpi_connection_t ip = {0};
    /* TODO: 如何判断一个数据是不是ssh
        1、SSH一般默认端口是22,并且应为要加密,长度应该是长度大于10(不一定准,测试长度大于7得出的结果和wirshark一样)
        2、一般开始链接的时候,有数据头有SSH-2.0版本的信息,可以比较字符串SSH-,并且建立连接后,之后这两个IP的这两个端口通讯一定是ssh
        3、数据段中有SSH-字段
    */
    if( NULL == app_buffer)
        return 1;

    if (NULL != ((dpi_pkt *)pkt_ptr)->ip_head_ptr && NULL != ((dpi_pkt *)pkt_ptr)->tcp_head_ptr)
    {
        ip.ipv4.src_port = ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_sport;
        ip.ipv4.dst_Port = ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_dport;
        ip.ipv4.dst_ip = ((dpi_pkt *)pkt_ptr)->ip_head_ptr->ip_daddr;
        ip.ipv4.src_ip = ((dpi_pkt *)pkt_ptr)->ip_head_ptr->ip_saddr;
    }

    // 匹配到字符串"SSH-"",说明之后这个ip和端口都是ssh包,添加进ssh链表
    // 如果有说明他在建立SSH连接,将他添加到他IP和端口记录到链表中,之后所有的这个IP和端口的通讯都是SSH
    //if (0 == strcmp("SSH", app_buffer))
    char strc[] = {0x53, 0x53, 0x48, 0x2d, 0x0};    // "SSH-"
    if(0 == memcmp(strc, app_buffer, 4))
        goto ANALYSIS_SSH_SUCCESS_ADDLIST;

    // 指向tcp头的指针是不是为空,并且字段大于10
    if (NULL != ((dpi_pkt *)pkt_ptr)->tcp_head_ptr && NULL != pkt_ptr && 10 < tcp_len)
    {
        u_int32_t port = htons(22);

        // 判断通信双方端口有没有22和通过长度判断
        if (port == ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_sport || port == ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_dport)
            goto ANALYSIS_SSH_SUCCESS_ADDLIST;
    }

    // 遍历已知的建立的ssh的链表中他的IP
    if (NULL !=  find_connect_ipproto_list(&ip, SSH))
        goto ANALYSIS_SSH_SUCCESS;

    return 1;

ANALYSIS_SSH_SUCCESS_ADDLIST:
    if (NULL == find_connect_ipproto_list(&ip, SSH))
        add_connect_ipproto_list(&ip, SSH);

ANALYSIS_SSH_SUCCESS:
    if (NULL != pkt_ptr)
    {
        ((dpi_pkt *)pkt_ptr)->ssh_head_ptr = app_buffer;
        ((dpi_pkt *)pkt_ptr)->ssh_len = tcp_len;
    }
    if (NULL != res_ptr)
        ++((dpi_result *)res_ptr)->tcp_proto_count[SSH];
    return 0;
}

u_int32_t analysis_ftp(void* pkt_ptr, void* app_buffer,  uint32_t tcp_len,  void* res_ptr)
{

    return 1;
}

u_int32_t analysis_tftp(void* pkt_ptr, void* udp_buffer,  uint32_t udp_len,  void* res_ptr)
{
    dpi_connection_t ip = {0};
    const char* data = NULL;
    uint16_t opcode = -1;

    if( NULL == udp_buffer)
        return 1;
    opcode = ntohs(*(uint16_t*)udp_buffer);

    // RRQ/WRQ数据包: Opcode:2字节 + Filename:至少1字节 + 1字节0 + Mode:至少4+ 1字节0
    if((opcode == 1  || opcode ==2) && udp_len >= TFTP_RWRQ_MINSIZE)
    {
        data = (uint8_t *)udp_buffer + 2 + strlen((uint8_t *)udp_buffer + 2) + 1;
        printf("    opcode:%d filename:%s, mode:%s\n", opcode, (uint8_t *)udp_buffer + 2, data);
        // 匹配 MODE
        for(int i=0 ; i<TFTP_RWRQ_MODE_MAX; ++i)
            if(0 == memcmp(data, g_tftp_rwrq_mode_strings[i], strlen(g_tftp_rwrq_mode_strings[i])+1))
                goto ANALYSIS_TFTP_SUCCESS;
    }
    return 1;

ANALYSIS_TFTP_SUCCESS:
    if (NULL != pkt_ptr)
    {
        ((dpi_pkt *)pkt_ptr)->tftp_head_ptr = udp_buffer;
        ((dpi_pkt *)pkt_ptr)->tftp_len = udp_len;
    }
    if (NULL != res_ptr)
        ++((dpi_result *)res_ptr)->udp_proto_count[TFTP];

    return 0; 
}

u_int32_t analysis_ntp(void* pkt_ptr, void* udp_buffer,  uint32_t udp_len,  void* res_ptr)
{
    
    return 1;
}
