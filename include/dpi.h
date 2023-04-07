#ifndef _DEF_H
#define _DEF_H

#include <pcap/pcap.h>

typedef struct _dpi_result
{
    void* pcap_handle;       // pcap文件指针
    unsigned int ether_count;   // 以太坊报文数量
    unsigned int ip_count;      // IP报文数量
    unsigned int tcp_count;    // TCP报文数量
    unsigned int udp_count;     // udp报文数量
}dpi_result, *dpi_result_ptr;

// 以太网头
typedef struct _dpi_eth_head
{
    uint8_t dstmac[6];  // 目标mac地址
    uint8_t srcmac[6];  // 源mac地址
    uint16_t eth_type;  // 网络层包类型
}dpi_eth_head, *dpi_eth_head_ptr;

// IP头
typedef struct _dpi_ip_head
{
#if __BYTE_ORDER == __LITTLE_ENDIAN	//大端
    unsigned int ip_headlen:4;  //版本 IPV4，IPV6
    unsigned int ip_version:4;  //IP头长度,一般20字节, 等于20/4
#elif __BYTE_ORDER == __BIG_ENDIAN	// 小端
    unsigned int ip_version:4; 
    unsigned int ip_headlen:4; 
#endif
    uint8_t tos;      //服务类型,一般没有使用，详细参考RFC
    uint16_t tot_len;  //header＋数据 总长度
    uint16_t id;       //IP 报文的唯一id，分片报文的id 相同，便于进行重组。
    uint16_t frag_off; //分片编号(标明是否分片)+分片偏移(偏移值/8)
    uint8_t ttl;       //路由器的跳转数
    uint8_t protocol;  //传输层协议, ICMP：1，TCP：6，UDP：17
    uint16_t check;    //IP header校验和,如果接收端收到报文进行计算如果校验和错误,直接丢弃。
    uint32_t saddr;    //源IP地址
    uint32_t daddr;    //目的IP地址
}dpi_ip_head, *dpi_ip_head_ptr;

typedef struct _dpi_pkt
{
//===========链路层(以太网)==========
    uint32_t  ether_len;    // 以太网层包长度
    dpi_eth_head* eth_head_ptr;     // 以太网层包头地址

//===========网络层(IP、ICMP和IGMP)==========
    uint32_t ip_len;
    dpi_ip_head* ip_head_ptr;

}dpi_pkt, *dpi_pkt_ptr;



/* dpi初始化,打开cap文件
@pcap_filename: cap文件路径
return: 打开cap文件失败返回空
*/
dpi_result* dpi_init(const char* pcap_filename);

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
void pcap_callback(u_char* user, const struct pcap_pkthdr* h,  const u_char* bytes); 

/* 解析处理以太网包报文
@pkt_ptr: 存放解析数据的地址
@package_buffer: 报文数据
@ether_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
    返回值: 网络层报文类型
*/
u_int32_t analysis_ether(dpi_pkt* pkt_ptr, void* ether_buffer,  uint32_t ether_len,  dpi_result* res_ptr);

/* 解析处理IP包报文
@pkt_ptr: 存放解析数据的地址
@package_buffer: 报文数据
@ether_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
    返回值: 网络层报文类型
*/
u_int32_t analysis_ip(dpi_pkt* pkt_ptr, void* ip_buffer,  uint32_t ip_len,  dpi_result* res_ptr);
#endif

