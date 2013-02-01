#pragma once

// Socket��ص�Э��ͷ������

typedef struct _iphdr //����IP��ͷ
{
	unsigned char h_lenver; //4λ�ײ�����+4λIP�汾��
	unsigned char tos; //8λ��������TOS
	unsigned short total_len; //16λ�ܳ��ȣ��ֽڣ�
	unsigned short ident; //16λ��ʶ
	unsigned short frag_and_flags; //3λ��־λ
	unsigned char ttl; //8λ����ʱ�� TTL
	unsigned char proto; //8λЭ�� (TCP, UDP ������)
	unsigned short checksum; //16λIP�ײ�У���
	unsigned int sourceIP; //32λԴIP��ַ
	unsigned int destIP; //32λĿ��IP��ַ
}IP_HEADER;

typedef struct _tcphdr //����TCP��ͷ
{
	unsigned short th_sport; //16λԴ�˿�
	unsigned short th_dport; //16λĿ�Ķ˿�
	unsigned int th_seq; //32λ���к�
	unsigned int th_ack; //32λȷ�Ϻ�
	unsigned char th_lenres; //4λ�ײ�����/4λ������
	unsigned char th_flag; //6λ��־λ
	unsigned short th_win; //16λ���ڴ�С
	unsigned short th_sum; //16λУ���
	unsigned short th_urp; //16λ��������ƫ����
}TCP_HEADER;

typedef struct psd_hdr //����TCPα��ͷ
{
	unsigned long saddr; //Դ��ַ
	unsigned long daddr; //Ŀ�ĵ�ַ
	char mbz;
	char ptcl; //Э������
	unsigned short tcpl; //TCP����
}PSD_HEADER;

typedef struct _udphdr //����UDP��ͷ
{
	unsigned short uh_sport;//16λԴ�˿�
	unsigned short uh_dport;//16λĿ�Ķ˿�
	unsigned short uh_len;//16λ����
	unsigned short uh_sum;//16λУ���
}UDP_HEADER;

typedef struct _icmphdr //����ICMP��ͷ(������������Ӧ)
{
	unsigned char i_type;//8λ����
	unsigned char i_code; //8λ����
	unsigned short i_cksum; //16λУ���
	unsigned short i_id; //ʶ��ţ�һ���ý��̺���Ϊʶ��ţ�
	unsigned short i_seq; //�������к�
	unsigned int timestamp;//ʱ���
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
