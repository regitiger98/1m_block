#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>
#include <fstream>
#include <iostream>
#include <unordered_set>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

#define IP_HDR_PROT	0x09
#define IP_HDR_TOT_LEN	0x02
#define TCP_HDR_LEN	0x0C
#define PROTOCOL_TCP 	0x06

struct Pkt_info
{
	int id;
	bool chk;
};

unordered_set<string> block;

void Read_hostfile(char *file){
	ifstream in(file);
	string line, host;

	while(getline(in, line)){
		host = line.substr(line.find(",")+1);
		block.insert(host);
	}
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}

bool Check_pkt(unsigned char *data)
{
	uint32_t ip_hdr_len, ip_pkt_len, tcp_hdr_len, tcp_data_len;
	string tcp_data, host;
	
	ip_hdr_len = ((*(uint8_t*)data) & 0x0F) * 4;
	ip_pkt_len = ntohs(*(uint16_t*)(data + IP_HDR_TOT_LEN));

	if(*(uint8_t*)(data + IP_HDR_PROT) != PROTOCOL_TCP)
	{
		printf("not TCP\n");
		return false;
	}
	tcp_hdr_len = (((*(uint8_t*)(data + ip_hdr_len + TCP_HDR_LEN)) & 0xF0) >> 4) * 4;
	
	if(ip_pkt_len == ip_hdr_len + tcp_hdr_len)
	{
		printf("no TCP Data\n");
		return false;
	}
	tcp_data_len = ip_pkt_len - ip_hdr_len - tcp_hdr_len;
	tcp_data = string((const char *)(data + ip_hdr_len + tcp_hdr_len), tcp_data_len);

	if(tcp_data.substr(0, 3) != "GET" &&
    	   tcp_data.substr(0, 3) != "PUT" &&
      	   tcp_data.substr(0, 4) != "POST" &&
      	   tcp_data.substr(0, 4) != "HEAD" &&
      	   tcp_data.substr(0, 6) != "DELETE" &&
     	   tcp_data.substr(0, 6) != "OPTION")
	{
		printf("no HTTP method\n");
		return false;
	}
	
	size_t pos = tcp_data.find("Host: ");
	if(pos == string::npos)
	{
		cout << "no \"Host: \" found\n";
		return false;
	}
	
	host = tcp_data.substr(pos + 6);
	pos = host.find("\r\n");
	host = host.substr(0, pos);
	cout << "HTTP host : " << host << endl;

	if(block.find(host) != block.end())
		return true;

	return false;		
}

/* returns packet id */
struct Pkt_info print_pkt (struct nfq_data *tb)
{
	struct Pkt_info ret;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int len;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		ret.id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, ret.id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	len = nfq_get_payload(tb, &data);
	ret.chk = Check_pkt(data);
	//dump(data, len);
	if (len >= 0)
		printf("payload_len=%d ", len);

	fputc('\n', stdout);

	return ret;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct Pkt_info pkt_info = print_pkt(nfa);
	printf("entering callback\n");
	if(pkt_info.chk == true)
	{
		printf("Packet Droped\n");
		return nfq_set_verdict(qh, pkt_info.id, NF_DROP, 0, NULL);
	}
	else
	{
		printf("Packet Accepted\n");
		return nfq_set_verdict(qh, pkt_info.id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	Read_hostfile(argv[1]);

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

