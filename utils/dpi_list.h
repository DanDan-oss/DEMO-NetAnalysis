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
    uint32_t node_count;    // 当前节点数,不算头节点
    proto_node_t* head;     // 头节点
}proto_list_t, *proto_list_ptr;


// 比较链表元素中存储数据的回调函数类型
typedef uint32_t (*compar_node_callback)(void* list_node, void* data);

// 打印函数回调函数类型,输出链表节点存储值的结构
typedef void (*list_print_callback)(void* node);


/* 创建初始化一个新链表
@return:
    失败 NULL
    成功 链表结构指针
*/
proto_list_t* proto_list_create();

/* 销毁链表
*/
void proto_list_delete(proto_list_t* list);

/* 添加一个新数据到链表中(尾插)
@return:
    失败 0
    成功 当前链表中拥有的节点数
*/
int proto_list_addNode(proto_list_t* list, void* data);

/*移除某一个节点,通过比较节点元素的属性指针比较
@return:
    失败 0
    成功 当前链表中拥有的节点数
*/
int proto_list_delNode(proto_list_t* list, void* data);

/* 移除某一个元素,通过回调函数比较节点存储数据
@list: 链表结构
@call_back: 比较查找元素是否相等的回调函数
@data: 查找的元素
@return:
    失败 NULL
    成功 节点指针
*/
int proto_list_delNode_compar(proto_list_t* list, compar_node_callback call_back, void* data);

/* 查找链表中是否存在某个元素
@list: 链表结构
@call_back: 比较查找元素是否相等的回调函数
@data: 查找的元素
@return:
    失败 NULL
    成功 节点指针
*/
void* proto_list_findNode_compar(proto_list_t* list, compar_node_callback call_back, void* data);

/* 遍历链表打印链表节点中的值
@list: 链表结构
@call_back: 打印存储数据的回调函数
*/
void ProtoListPrint(proto_list_t* list, list_print_callback callback);

// 测试链表结构
void ProtoDubgPrint();
#endif