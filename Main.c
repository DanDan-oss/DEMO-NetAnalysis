#include <stdio.h>
#include "dpi.h"
#include "./utils/dpi_list.h"

#define PCAP_FILE_PATH "../pcap/test.pcap"

int main(int argc, char* argv[])
{
	dpi_result_ptr res_ptr = NULL;

	// 初始化pcap文件
	
	if(2 ==argc)
		res_ptr = dpi_init(argv[1]);
	else
		res_ptr = dpi_init(PCAP_FILE_PATH);
		
	if(NULL == res_ptr)
		return -1;

	// 数据处理
	dpi_loop(res_ptr);
	
	// 释放pcap文件资源
	dpi_fini(res_ptr);
	
	// 测试链表
	//proto_list_t* list = proto_list_create();
	//proto_list_delete(list);
	//printf("哈哈");
	return 0;
}
