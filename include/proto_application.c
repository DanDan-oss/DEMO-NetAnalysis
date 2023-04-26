#include "dpi.h"
#include "proto_application.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

protocl_tcp_analyze_func_t protocl_analyze_funcs[PROTOCOL_TCP_MAX]=
{
    analysis_http,
    analysis_ssh,
    analysis_ftp
};

const char* protocl_tcp_string[PROTOCOL_TCP_MAX]=
{
    PROTO_TCP_STRING
};

//  TCP协议下
u_int32_t analysis_http(void* pkt_ptr, void* app_buffer,  uint32_t tcp_len,  void* res_ptr)
{
    return 0;
}


u_int32_t analysis_ssh(void* pkt_ptr, void* app_buffer,  uint32_t tcp_len,  void* res_ptr)
{
    dpi_connection_t tcp = {0};
    /* TODO: 如何判断一个数据是不是ssh
        1、SSH一般默认端口是22,并且应为要加密,长度应该是长度大于10(不一定准,测试长度大于7得出的结果和wirshark一样)
        2、一般开始链接的时候,有数据头有SSH-2.0版本的信息,可以比较字符串SSH-,并且建立连接后,之后这两个IP的这两个端口通讯一定是ssh
        3、数据段中有SSH-字段
    */
    if( NULL == app_buffer)
        return 0;

    if (NULL != ((dpi_pkt *)pkt_ptr)->ip_head_ptr && NULL != ((dpi_pkt *)pkt_ptr)->tcp_head_ptr)
    {
        tcp.ipv4.src_port = ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_sport;
        tcp.ipv4.dst_Port = ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_dport;
        tcp.ipv4.dst_ip = ((dpi_pkt *)pkt_ptr)->ip_head_ptr->ip_daddr;
        tcp.ipv4.src_ip = ((dpi_pkt *)pkt_ptr)->ip_head_ptr->ip_saddr;
    }

    // 判断数据头有没有 SSH- 字样,
    // 如果有说明他在建立SSH连接,将他添加到他IP和端口记录到链表中,之后所有的这个IP和端口的通讯都是SSH
    if (0 == strcmp("SSH-", app_buffer))
    {
        if (NULL != ((dpi_pkt *)pkt_ptr)->tcp_head_ptr || NULL != pkt_ptr)
        {
            ((dpi_pkt *)pkt_ptr)->ssh_head_ptr = app_buffer;
            ((dpi_pkt *)pkt_ptr)->ssh_len = tcp_len;
        }
        // 匹配到字符串 SSH-,说明之后这个ip和端口都是ssh包,添加进ssh链表
        if(0<find_connect_ipproto_list(&tcp, SSH))
            add_connect_ipproto_list(&tcp, SSH);
        if (NULL != res_ptr)
            ++((dpi_result *)res_ptr)->tcp_proto_count[SSH];
        return 1;
    }

    // 指向tcp头的指针是不是为空,并且字段大于10
    if (NULL != ((dpi_pkt *)pkt_ptr)->tcp_head_ptr && NULL != pkt_ptr && 10 < tcp_len)
    {
        u_int32_t port = ntohs(22);

        // 判断通信双方端口有没有22+通过长度判断
        if (port == ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_sport || port == ((dpi_pkt *)pkt_ptr)->tcp_head_ptr->tcp_dport)
        {
            ((dpi_pkt *)pkt_ptr)->ssh_head_ptr = app_buffer;
            ((dpi_pkt *)pkt_ptr)->ssh_len = tcp_len;
            if(0<find_connect_ipproto_list(&tcp, SSH))
                add_connect_ipproto_list(&tcp, SSH);
            if (NULL != res_ptr)
                ++((dpi_result *)res_ptr)->tcp_proto_count[SSH];
            return 1;
        }
    }

    // 遍历已知的建立的ssh的链表中他的IP
    if (0 < find_connect_ipproto_list(&tcp, SSH))
    {
        ((dpi_pkt *)pkt_ptr)->ssh_head_ptr = app_buffer;
        ((dpi_pkt *)pkt_ptr)->ssh_len = tcp_len;
        if (NULL != res_ptr)
            ++((dpi_result *)res_ptr)->tcp_proto_count[SSH];
        return 1;
    }
    return 0;
}

u_int32_t analysis_ftp(void* pkt_ptr, void* app_buffer,  uint32_t tcp_len,  void* res_ptr)
{

    return 0;
}