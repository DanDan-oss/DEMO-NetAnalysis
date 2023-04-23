
#include "proto_list.h"


proto_list_t* g_ipproto_connections[PROTOCOL_TCP_MAX] = {0};

void init_connect_ipproto_list()
{
    for(int i=0; i<sizeof(g_ipproto_connections); ++i)
        g_ipproto_connections[i] = proto_list_create();
}

void fini_connect_ipproto_list()
{
    for(int i=0; i<sizeof(g_ipproto_connections); ++i)
        proto_list_delete(g_ipproto_connections[i]);
}

uint32_t add_connect_ipproto_list(dpi_connection_t* connect, TCP_PROTOCOL proto)
{
    if(proto > PROTOCOL_TCP_MAX || NULL == connect)
        return -1;
    return proto_list_addNode(g_ipproto_connections[proto], connect);
}

// 比较两个ip proto回调函数
uint32_t compar(void* list_node, void* data)
{
    dpi_connection_t* param_one = (dpi_connection_t*)list_node;
    dpi_connection_t* param_two = (dpi_connection_t*)data;

    if(NULL == param_one || NULL == param_two)
        return -1;
    return memcmp(param_one, param_two, sizeof(dpi_connection_t));
} 

uint32_t del_connect_ipproto_list(dpi_connection_t* connect, TCP_PROTOCOL proto)
{
    if(proto > PROTOCOL_TCP_MAX || NULL == connect)
        return -1;

    proto_list_delNode_compar(g_ipproto_connections[proto], compar, connect);
}


