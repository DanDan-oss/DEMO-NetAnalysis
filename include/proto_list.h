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

// 比较两个节点ip、port四元组是否相等的回调函数
uint32_t compar(void* list_node, void* data);

/* 初始化tcp协议组链表,当前的协议组PROTO_TCP_STRING
@return:
*/
void init_connect_ipproto_list();

/* 销毁链表
@return:
*/
void fini_connect_ipproto_list();

/* 向协议组中的链表添加一个链接信息
@connect: 要存储的四元组(IP+PORT)
@proto: 协议类型
@return:
    失败 -1
    成功 当前链表中元素个数
*/
uint32_t add_connect_ipproto_list(dpi_connection_t* connect, TCP_PROTOCOL proto);

/* 向协议组中的链表删除一个链接信息
@connect: 要删除的四元组(IP+PORT)
@proto: 协议类型
@return:
    失败 0或者-1
    成功 当前链表中元素个数
*/
uint32_t del_connect_ipproto_list(dpi_connection_t* connect, TCP_PROTOCOL proto);

/* 在协议组中的链表查找一个链接信息
@connect: 要查找的四元组(IP+PORT)
@proto: 协议类型
@return:
    失败 0或者-1
    成功 节点指针
*/
dpi_connection_t* find_connect_ipproto_list(dpi_connection_t* connect, TCP_PROTOCOL proto);

/* 遍历打印协议组中所有链表四元组
*/
u_int32_t show_proto_all();

/*打印协议组中某个协议的链表四元组
*/
uint32_t show_connect_ipproto_list(proto_list_t* connect, TCP_PROTOCOL proto);

/* 打印IP四元组回调函数
*/
void print_ipproto_list(void* node);

#endif