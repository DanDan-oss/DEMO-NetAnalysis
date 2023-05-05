#include <stdlib.h>
#include <string.h>

#include "dpi.h"


dpi_result* dpi_init(const uint8_t* pcap_filename)
{
    char ebuf[PCAP_ERRBUF_SIZE] = {0};  // pcap错误消息存放buffer
    pcap_t* pcap=NULL;
    dpi_result* result = NULL;

    // 打开cap文件
    pcap = pcap_open_offline(pcap_filename, ebuf);
	if(NULL == pcap)
	{
		printf("Error, cap file open fail: %s\n", ebuf);
		return NULL;
	}
    if(NULL == (result = malloc(sizeof(dpi_result))))
    {
        pcap_close(pcap);
        return NULL;
    }
    memset(result, 0, sizeof(dpi_result));
    result->pcap_handle = pcap;
    return result;
}

void dpi_fini(dpi_result* res_ptr)
{
    if( NULL == res_ptr) //传进来的是空指针
        return;

    if(NULL != res_ptr->pcap_handle)
        pcap_close(res_ptr->pcap_handle);
    free(res_ptr);
    res_ptr = NULL;
    return;
}

void dpi_loop(dpi_result* res_ptr)
{
    pcap_t* pcap = res_ptr->pcap_handle;
    if(NULL == pcap)
        return;
    memset(res_ptr, 0, sizeof(dpi_result));
    res_ptr->pcap_handle = pcap;

    // 初始化protolist
    init_connect_ipproto_list();

    // typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
    pcap_loop(pcap, 0, &pcap_callback, (u_int8_t*)res_ptr);

    printf("数据处理: 以太网包数量有%d\n", res_ptr->ether_count);
	printf("数据处理: IP包数量有%d\n", res_ptr->ip_count);
    printf("数据处理: ICPM包数量有%d\n", res_ptr->icpm_count);
    printf("数据处理: TCP包数量有%d\n", res_ptr->tcp_count);
    printf("数据处理: UDP包数量有%d\n", res_ptr->udp_count);
    for(int i=0; i<PROTOCOL_TCP_MAX; ++i)
        printf("数据处理TCP: %s包数量有%d\n", g_protocl_tcp_string[i], res_ptr->tcp_proto_count[i]);
    
    for(int i=0; i<PROTOCOL_UDP_MAX; ++i)
        printf("数据处理UDP: %s包数量有%d\n", g_protocl_udp_string[i], res_ptr->udp_proto_count[i]);

    show_proto_all();
    // 释放 protolist
    fini_connect_ipproto_list();
    
    return;
}

void pcap_callback(u_int8_t* user, const struct pcap_pkthdr* h,  const u_int8_t* bytes)
{
   dpi_result* res_ptr= (dpi_result*)user;
   dpi_pkt pkt = {0};
   u_int32_t eth_type=0;
// 以太网包解析, 处理的每一个包都是以太网包
    eth_type = analysis_ether( &pkt, (void*)bytes, h->caplen, res_ptr);
    return;
}

