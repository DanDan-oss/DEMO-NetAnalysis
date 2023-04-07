#include <stdio.h>
#include "dpi.h"

#define PCAP_FILE_PATH "/home/kali/Documents/CodeHub/Dpi/pcap/test.pcap"

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
	
	return 0;
}
