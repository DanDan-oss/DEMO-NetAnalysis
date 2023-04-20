#include "dpi_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 创建一个新节点

proto_list_t* proto_list_create()
{
    proto_list_t* new_list = NULL;
    proto_list_node_t* node_head = NULL;

    if(NULL == (new_list = malloc(sizeof(proto_list_t))))
        return NULL;

    memset(new_list, 0, sizeof(proto_list_t));
    if(NULL == (node_head = malloc(sizeof(proto_list_node_t))))
    {
        free(new_list);
        return NULL;
    }
    memset(node_head, 0, sizeof(proto_list_node_t));
    new_list->head = node_head;
    node_head->Back =  node_head->Next = node_head;
    return new_list;
}

void proto_list_delete(proto_list_t* list)
{
    proto_list_node_t* node_head = NULL;
    proto_list_node_t* node_last = NULL;
    if(NULL == list)
        return;

    node_head = list->head;
    if(NULL == node_head)
    {
        free(list);
        printf("free\n");
        list = NULL;
        return ;
    }

    node_last = node_head->Next;
    node_head->Next = NULL;
    while (NULL != node_last)
    {
        proto_list_node_t* node_temp = node_last->Next;
        free(node_last->data);
        free(node_last);
        printf("free\n");
        node_last = node_temp;
    }
    free(list);
    printf("free\n");
    list = NULL;
    return;
}

// 添加一个新数据到链表中(尾插)
int proto_list_addNode(proto_list_t* list, void* data)
{
    proto_list_node_t* node_last = NULL;
    proto_list_node_t* new_node = NULL;

    if(NULL == list || NULL == data )
        return 0;
    
    node_last = list->head->Back;
    new_node = malloc(sizeof(proto_list_node_t));
    if(NULL == new_node)
        return 0;
    memset(new_node, 0, sizeof(proto_list_node_t));

    list->head->Back = new_node;
    new_node ->Next = list->head;

    node_last->Next = new_node;
    new_node->Back = node_last;
    list->node_count++;
    return list->node_count;
}

// 移除某一个节点
int proto_list_delNode(proto_list_t* list, void* data)
{
    proto_list_node_t* node_head = NULL;
    proto_list_node_t* node_last = NULL;

    if(NULL == list || NULL == data)
        return 0;

    node_head = list->head;
    node_last = node_head->Next;
    while (node_last != node_head)
    {
        if(node_last->data != data)
        {
            node_last=  node_last->Next;
            continue;
        }
        node_last->Next->Back = node_last->Back;
        node_last->Back->Next = node_last->Next;
        free(node_last->data);
        free(node_last);
        return 1;
    }
    
return 0;
}

