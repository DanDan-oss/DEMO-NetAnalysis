#include "dpi.h"
#include "proto_application.h"
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
    /* TODO: 如何判断一个数据是不是ssh
        1、SSH一般默认端口是22,并且应该是长度大于7(不一定准,测试长度大于7得出的结果和wirshark一样)
        2、一般开始链接的时候,有数据头有SSH-2.0版本的信息,可以比较字符串SSH-
        3、数据段中有SSH-字段
    */
    if( 7> tcp_len || NULL == app_buffer)
        return 0;

    // 指向tcp头的指针是不是为空
    if(NULL != ((dpi_pkt*)pkt_ptr)->tcp_head_ptr  || NULL != pkt_ptr )
    {
        // tcp头指针不为空,判断通信双方端口有没有22
        u_int32_t port = ntohs(22);
        if( port == ((dpi_pkt*)pkt_ptr)->tcp_head_ptr->tcp_sport || port == ((dpi_pkt*)pkt_ptr)->tcp_head_ptr->tcp_dport)
        {
            ((dpi_pkt*)pkt_ptr)->ssh_head_ptr = app_buffer;
            ((dpi_pkt*)pkt_ptr)->ssh_len = tcp_len;
            if(NULL != res_ptr)
                ++ ((dpi_result*)res_ptr)->tcp_proto_count[SSH];
            return 1;
        }
    }

    // 判断数据头有没有 SSH- 字样
    if(0 == strcmp("SSH-", app_buffer))
    {
        if(NULL != ((dpi_pkt*)pkt_ptr)->tcp_head_ptr  || NULL != pkt_ptr )
        {
             ((dpi_pkt*)pkt_ptr)->ssh_head_ptr = app_buffer;
             ((dpi_pkt*)pkt_ptr)->ssh_len = tcp_len;
        }
        if(NULL != res_ptr)
            ++ ((dpi_result*)res_ptr)->tcp_proto_count[SSH];
        return 1;
    }
    return 0;
}

u_int32_t analysis_ftp(void* pkt_ptr, void* app_buffer,  uint32_t tcp_len,  void* res_ptr)
{

    return 0;
}