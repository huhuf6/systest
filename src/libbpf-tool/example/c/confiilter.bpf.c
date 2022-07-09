#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "confiilter.h"

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

int ifindex = 0;
__u64 traffic = 0;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");




SEC("tp_btf/netif_receive_skb")
int BPF_PROG(netif_receive_skb, struct sk_buff *skb)
{
void *data = (void *)(long)skb->data;
    if (skb->dev->ifindex == ifindex) {
	struct ethhdr *eth = data;
	char * find =eth;
	struct packet p = {};
	//p.l3proto = bpf_htons(eth->h_proto);
	bpf_core_read(&p.l3proto,sizeof(eth->h_proto),find-2);
	p.l3proto=bpf_htons(p.l3proto);
	
	if (p.l3proto == ETH_P_IP) 
	{
		struct iphdr *iph;
		iph = data + sizeof(struct ethhdr)-14;
		BPF_CORE_READ_INTO(&p.src,iph,saddr);
		BPF_CORE_READ_INTO(&p.dst,iph,daddr);
		BPF_CORE_READ_INTO(&p.l4proto,iph,protocol);
		//bpf_probe_read_kernel(&p.src,sizeof(iph->saddr),iph->saddr);
		//bpf_probe_read(&p.dst,sizeof(iph->daddr),iph->daddr);
		//bpf_probe_read(&p.l4proto,sizeof(iph->protocol),iph->protocol);
		p.sport = p.dport = 0;
		bpf_printk("%lX \n",p.l4proto); 
		BPF_CORE_READ_INTO(&p.packetsize,iph,tot_len);
		if (p.l4proto == IPPROTO_TCP) 
		{
		struct tcphdr *tcph;
		tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr)-14;
		BPF_CORE_READ_INTO(&p.sport,tcph,source);
		BPF_CORE_READ_INTO(&p.dport,tcph,dest);
		}
		else if (p.l4proto == IPPROTO_UDP) 
		{
		struct udphdr *udph;
		udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr)-14;
		BPF_CORE_READ_INTO(&p.sport,udph,source);
		BPF_CORE_READ_INTO(&p.dport,udph,dest);
		}
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &p, sizeof(p));
		bpf_printk("%d %d\n",p.sport,p.dport); 
	}
	
}

    if (skb->dev->ifindex == ifindex) {
        traffic += skb->data_len;
    }
    bpf_printk("get a packet and ifindex is %d,target if is :%d\n",skb->dev->ifindex,ifindex); 
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
