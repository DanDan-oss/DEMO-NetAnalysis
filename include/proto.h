#ifndef _PROTOCOL_H
#define _PROTOCOL_H


#include <netinet/in.h>

#define  ETH_P_IP 0x0800 //IP协议
#define  ETH_P_ARP 0x0806  //地址解析协议(Address Resolution Protocol)
#define  ETH_P_RARP 0x8035  //返向地址解析协议(Reverse Address Resolution Protocol)
#define  ETH_P_IPV6 0x86DD  //IPV6协议

struct dpi_result;
struct dpi_pkt;

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
    uint8_t ip_headlen : 4;  //版本 IPV4，IPV6
    uint8_t ip_version : 4;  //IP头长度,,一般值是5,一个位代表4个字节的长度.首部大小5*4=20字节
#elif __BYTE_ORDER == __BIG_ENDIAN	// 小端
    uint8_t ip_version:4; 
    uint8_t ip_headlen:4; 
#endif

    uint8_t ip_tos;        //服务类型,一般没有使用，详细参考RFC
    uint16_t ip_tot_len;  //header＋数据 总长度
    uint16_t ip_id;       //IP 报文的唯一id，分片报文的id 相同，便于进行重组

    //uint16_t ip_frag_off; //分片编号(标明是否分片)+分片偏移(偏移值/8)
    
#if __BYTE_ORDER == __LITTLE_ENDIAN	//大端
    uint16_t ip_frag_off_1 : 5;    //偏移值前5位
    uint16_t ip_frag_num : 3;     //分片编号
    uint16_t ip_frag_off_2 : 8;    //偏移值后8位
#elif __BYTE_ORDER == __BIG_ENDIAN	// 小端
    uint16_t ip_frag_num : 3;
    uint16_t ip_frag_off_1 : 5;
    uint16_t ip_frag_off_2 : 8; 
#endif

    uint8_t ip_ttl;       //路由器的跳转数
    uint8_t ip_proto;  //传输层协议, ICMP：1，TCP：6，UDP：17
    uint16_t ip_check;    //IP header校验和,如果接收端收到报文进行计算如果校验和错误,直接丢弃。
    uint32_t ip_saddr;    //源IP地址
    uint32_t ip_daddr;    //目的IP地址
}dpi_ip_head, *dpi_ip_head_ptr;

// tcp头
typedef struct _dpi_tcp_head
{
	uint16_t tcp_sport;     // 源端口
	uint16_t tcp_dport;     // 目标端口
    uint32_t tcp_seq;
    uint32_t tcp_ack;

    //uint16_t flags;     // 4位头首部长度;  6位保留位; 6位标志位(URG、ACK、PSH、PST、SYN、FIN);
#if __BYTE_ORDER == __LITTLE_ENDIAN	//大端
	uint16_t res1:4;    // 6位保留位中的前4位
	uint16_t tcp_head_Len : 4;    // 4位头首部长度
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;    // 6位保留位中的后2位
#elif __BYTE_ORDER == __BIG_ENDIAN	// 小端
	uint16_t tcp_head_Len : 4;    // 4位头首部长度
	uint16_t res1:4;    // 6位保留位中的前4位
	uint16_t res2:2;    // 6位保留位中的后2位
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#endif

	uint16_t tcp_window;    // 16位滑动窗口大小
	uint16_t tcp_check;     // 16位TCP头校验和
	uint16_t tcp_urg_ptr;   // 16位紧急指针
}dpi_tcp_head, *dpi_tcp_head_ptr;

/* 解析处理以太网包报文
@pkt_ptr: 存放解析数据的地址
@ether_buffer: 报文数据
@ether_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
    返回值: 网络层报文类型
*/
u_int32_t analysis_ether(void* pkt_ptr, void* ether_buffer,  uint32_t ether_len,  void* res_ptr);

/* 解析处理IP包报文
@pkt_ptr: 存放解析数据的地址
@ip_buffer: 报文数据
@ip_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
    返回值: 网络层报文类型
*/
u_int32_t analysis_ip(void* pkt_ptr, void* ip_buffer,  uint32_t ip_len,  void* res_ptr);


/* 解析处理IP包报文
@pkt_ptr: 存放解析数据的地址
@tcp_buffer: 报文数据
@tcp_len: 报文长度
@ret_ptr: 累计记录各类报文数量的地址可传NULL
    返回值: 网络层报文类型
*/
u_int32_t analysis_tcp(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);



// ============== 解析应用层协议==================
// 应用层协议太多,并且还有自定义协议格式不固定,所以把每种解析函数写到函数指针的数组中
// 解析时,遍历数组调用函数,根据函数返回值判断协议类型
// ===============================================

// 当前HTTP下可以解析的应用层协议
typedef enum _TCP_PROTOCOL
{
    SSH=0,
    HTTP=1,
    FTP=2,
    PROTOCOL_TCP_MAX
}TCP_PROTOCOL;

// HTTP下的应用层协议函数类型定义
typedef u_int32_t (*protocl_analyze_func_t)(void*, void*,  uint32_t,  void*);
// HTTP下的应用层协议函数数组定义

u_int32_t analysis_http(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);
u_int32_t analysis_ssh(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);
u_int32_t analysis_ftp(void* pkt_ptr, void* tcp_buffer,  uint32_t tcp_len,  void* res_ptr);


#endif