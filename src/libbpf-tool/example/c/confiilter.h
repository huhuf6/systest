// SPDX-License-Identifier: GPL-2.0

#ifndef __CONFIILTER_H
#define __CONFIILTER_H

struct packet {
	unsigned int src;
	unsigned int dst;
	__be16 l3proto;
	unsigned char l4proto;
	unsigned short sport;
	unsigned short dport;
	unsigned short packetsize;
};
















#endif 
