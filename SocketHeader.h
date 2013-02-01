#pragma once

// Socket相关的协议头部定义

typedef struct _iphdr //定义IP报头
{
	unsigned char h_lenver; //4位首部长度+4位IP版本号
	unsigned char tos; //8位服务类型TOS
	unsigned short total_len; //16位总长度（字节）
	unsigned short ident; //16位标识
	unsigned short frag_and_flags; //3位标志位
	unsigned char ttl; //8位生存时间 TTL
	unsigned char proto; //8位协议 (TCP, UDP 或其他)
	unsigned short checksum; //16位IP首部校验和
	unsigned int sourceIP; //32位源IP地址
	unsigned int destIP; //32位目的IP地址
}IP_HEADER;

typedef struct _tcphdr //定义TCP报头
{
	unsigned short th_sport; //16位源端口
	unsigned short th_dport; //16位目的端口
	unsigned int th_seq; //32位序列号
	unsigned int th_ack; //32位确认号
	unsigned char th_lenres; //4位首部长度/4位保留字
	unsigned char th_flag; //6位标志位
	unsigned short th_win; //16位窗口大小
	unsigned short th_sum; //16位校验和
	unsigned short th_urp; //16位紧急数据偏移量
}TCP_HEADER;

typedef struct psd_hdr //定义TCP伪报头
{
	unsigned long saddr; //源地址
	unsigned long daddr; //目的地址
	char mbz;
	char ptcl; //协议类型
	unsigned short tcpl; //TCP长度
}PSD_HEADER;

typedef struct _udphdr //定义UDP报头
{
	unsigned short uh_sport;//16位源端口
	unsigned short uh_dport;//16位目的端口
	unsigned short uh_len;//16位长度
	unsigned short uh_sum;//16位校验和
}UDP_HEADER;

typedef struct _icmphdr //定义ICMP报头(回送与或回送响应)
{
	unsigned char i_type;//8位类型
	unsigned char i_code; //8位代码
	unsigned short i_cksum; //16位校验和
	unsigned short i_id; //识别号（一般用进程号作为识别号）
	unsigned short i_seq; //报文序列号
	unsigned int timestamp;//时间戳
}ICMP_HEADER;

USHORT CheckSum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while(size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if(size)
	{
		cksum += *(UCHAR*)buffer;
	}

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (USHORT)(~cksum);
}
