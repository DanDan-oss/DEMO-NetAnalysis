#ifndef _DEF_H
#define _DEF_H 1

#include <pcap/pcap.h>
#include "proto_datalink.h"
#include "proto_network.h"
#include "proto_transport.h"
#include "proto_application.h"
#include "proto_list.h"

#define  ETH_P_IP 0x0800 //IP协议
#define  ETH_P_ARP 0x0806  //地址解析协议(Address Resolution Protocol)
#define  ETH_P_RARP 0x8035  //返向地址解析协议(Reverse Address Resolution Protocol)
#define  ETH_P_IPV6 0x86DD  //IPV6协议


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

//===========应用层==========
    uint32_t tcp_proto_count[PROTOCOL_TCP_MAX];

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
    uint32_t ssh_len;
    void* ssh_head_ptr;

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

