#ifndef _DPI_LIST_H
#define _DPI_LIST_H 1

#include <netinet/in.h>

// 链表节点结构
typedef struct _proto_node
{
    void* data;
    struct _proto_node* Back;
    struct _proto_node* Next;
}proto_node_t, *proto_node_ptr;

// 链表
typedef struct _proto_list
{
    uint32_t node_count;
    proto_node_t* head;
}proto_list_t, *proto_list_ptr;

// 创建一个新链表
proto_list_t* proto_list_create();

void proto_list_delete(proto_list_t* list);

// 添加一个新数据到链表中(尾插)
int proto_list_addNode(proto_list_t* list, void* data);

// 移除某一个节点
int proto_list_delNode(proto_list_t* list, void* data);

/* 移除某一个元素,通过回调函数
    回调函数中自行比较数据结构,相等返回0,不相等返回非0
*/
typedef uint32_t (*compar_node_callback)(void* list_node, void* data);
int proto_list_delNode_compar(proto_list_t* list, compar_node_callback call_back, void* data);

// 遍历链表打印链表节点中的值
typedef void (*list_print_callback)(void* node);
void ProtoListPrint(proto_list_t* list, list_print_callback callback);


// 测试链表结构
void ProtoDubgPrint();

#endif