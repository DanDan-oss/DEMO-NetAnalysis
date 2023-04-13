#ifndef _DEF_H
#define _DEF_H

#include <pcap/pcap.h>
#include "proto.h"

// dpi报文计数器
typedef struct _dpi_result
{
    void* pcap_handle;       // pcap文件指针

//===========链路层(以太网)==========
    uint32_t ether_count;   // 以太坊报文数量

//===========网络层(IP、ARP、RARP和IGMP)==========
    uint32_t ip_count;      // IP报文数量

//===========传输层(ICMP、TCP和UDP)==========
    uint32_t tcp_count;    // TCP报文数量
    uint32_t udp_count;     // udp报文数量
    uint32_t icpm_count;    // icpm

}dpi_result, *dpi_result_ptr;

// 记录当前报文各个层的地址和长度
typedef struct _dpi_pkt
{
//===========链路层(以太网)==========
    uint32_t  ether_len;    // 以太网层包长度
    dpi_eth_head* eth_head_ptr;     // 以太网层包头地址

//===========网络层(IP、ARP、RARP和IGMP)==========
    uint32_t ip_len;
    dpi_ip_head* ip_head_ptr;


//===========传输层(ICMP、TCP和UDP)==========
    uint32_t tcp_len;
    dpi_tcp_head* tcp_head_ptr;

//===========应用层协议(HTTP、SSH和FTP)==========

}dpi_pkt, *dpi_pkt_ptr;


/* dpi初始化,打开cap文件
@pcap_filename: cap文件路径
return: 打开cap文件失败返回空
*/
dpi_result* dpi_init(const uint8_t* pcap_filename);

/*  dpi释放资源
@pdpi_res: 自定义dpi文件信息结构
*/
void dpi_fini(dpi_result* res_ptr);

/* dpi业务处理,处理解析pcap文件的代码
@res_ptr: 自定义dpi文件信息结构
*/
void dpi_loop(dpi_result* res_ptr);

/* dpi解析每条报文数据回调函数,处理每一条报文的回调函数
@user: 自定义参数,pcap_loop传入
@h: 系统解析的报文客户信息
@bytes: 报文数据
*/
void pcap_callback(uint8_t* user, const struct pcap_pkthdr* h,  const uint8_t* bytes); 

#endif

