#ifndef _DPI_LIST_H
#define _DPI_LIST_H 1

#include <netinet/in.h>

// 链表节点结构
typedef struct _proto_list_node
{
    void* data;
    struct _proto_list_node* Back;
    struct _proto_list_node* Next;
}proto_list_node_t, *proto_list_node_ptr;


// 链表
typedef struct _proto_list
{
    uint32_t node_count;
    proto_list_node_t* head;
}proto_list_t, *proto_list_ptr;

// 创建一个新节点
proto_list_t* proto_list_create();

void proto_list_delete(proto_list_t* list);

// 添加一个新数据到链表中(尾插)
int proto_list_addNode(proto_list_t* list, void* data);

// 移除某一个节点
int proto_list_delNode(proto_list_t* list, void* data);

#endif