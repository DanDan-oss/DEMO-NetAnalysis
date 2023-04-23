#ifndef _PROTO_LIST_H
#define _PROTO_LIST_H

#include "dpi.h"
#include "../utils/dpi_list.h"

// IPV4四元组
typedef struct _ipv4_port_pair
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_Port;
}ipv4_port_pair_t,*ipv4_port_pair_ptr;

// 定义一个链接的信息(四元组ipv4)
typedef struct _dpi_connection
{
    ipv4_port_pair_t ipv4;

    // 后面可以添加IPV6...
}dpi_connection_t, *dpi_connection_ptr;

extern proto_list_t* g_ipproto_connections[PROTOCOL_TCP_MAX];

/* 初始化tcp协议组链表,当前的协议组PROTO_TCP_STRING

*/
void init_connect_ipproto_list();

/* 销毁链表

*/
void fini_connect_ipproto_list();

/* 向connect协议组中的链表添加一个链接信息
    
*/
uint32_t add_connect_ipproto_list(dpi_connection_t* connect, TCP_PROTOCOL proto);

// 比较两个节点ip、port四元组是否相等的回调函数
uint32_t compar(void* list_node, void* data);
/* 向connect协议组中的链表删除一个链接信息
 
*/
uint32_t del_connect_ipproto_list(dpi_connection_t* connect, TCP_PROTOCOL proto);

#endif