#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
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

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);
		dump(data, ret);

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	// deny_domain 을 cb 의 마지막 인자로 주려했지만 오류가 나서 해결이 안 되어
	// GPT 사용해서 해결했습니다.
	char *deny_domain = (char *)data;
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");

	unsigned char *pkt_data;

	// 페이로드가 없으면 허용
	int payload_len = nfq_get_payload(nfa, &pkt_data);
	if (payload_len < 0) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	// IP 프로토콜이 아니라면 HTTP가 아님 - 허용
	struct iphdr *ip_h = (struct iphdr *)pkt_data;
	if (ip_h->protocol != IPPROTO_TCP) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	// TCP 헤더 길이 계산
	unsigned int ip_header_len = ip_h->ihl * 4;
	struct tcphdr *tcp_h = (struct tcphdr *)(pkt_data + ip_header_len);
	
	unsigned int tcp_header_len = tcp_h->doff * 4;
	char *http_payload = (char *)(pkt_data + ip_header_len + tcp_header_len);
	int http_payload_len = payload_len - (ip_header_len + tcp_header_len);

	if (http_payload_len <= 0) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	// 일치하는 문자여 찾기! - AI 사용했습니다.
	char *host_start = strstr(http_payload, "Host: ");
	if (host_start == NULL) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	// "Host: " 문자열 다음부터 시작
	host_start += 6;

	char *host_end = strstr(host_start, "\r\n");
	if (host_end == NULL) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	int host_len = host_end - host_start;
	char extracted_host[256];
	if (host_len > 0 && host_len < sizeof(extracted_host)) {
		strncpy(extracted_host, host_start, host_len);
		extracted_host[host_len] = '\0';

		// 도메인과 문자열 비교
		if (strcmp(extracted_host, deny_domain) == 0) {
			printf("거부된 요청! HOST :{%s}\n", extracted_host);
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
		printf("허용된 요청! HOST : {%s}\n", extracted_host);
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("입력 샘플 : netfilter-test test.gilgil.net");
		exit(1);
	}
	char *deny_domain = argv[1];

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
	qh = nfq_create_queue(h,  0, &cb, deny_domain);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

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
