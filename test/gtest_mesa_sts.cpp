#include <pcap.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

#include "gtest/gtest.h"

extern "C" {
#include "mesa_sts.h"
}

#define MAX_PKT_CNT 1

static int read_pcap_and_judge_randomness(const char* pcap_file, struct sts_result* result)
{
    pcap_t *handle;
    struct pcap_pkthdr *header; // pcap报文头部结构
    const u_char *packet; // 报文数据指针
    char errbuf[PCAP_ERRBUF_SIZE];
    char content[2048] = {0};
    int content_len = 0;
    int payload_len;
	char *payload;
    int pkt_cnt = 0;

    handle = pcap_open_offline(pcap_file, errbuf);
    while (pcap_next_ex(handle, &header, &packet) > 0) {
		unsigned short eth_type = ntohs(*(unsigned short *)(packet + 12));
		if (eth_type == ETH_P_IP) {
            int l4_proto = *(unsigned char *)(packet + sizeof(struct ethhdr) + 9);
            if (l4_proto == IPPROTO_TCP) {
                payload_len = header->caplen - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr);
			    payload = (char *)packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
            } else if (l4_proto == IPPROTO_UDP) {
                payload_len = header->caplen - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
                payload = (char *)packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
            } else {
                continue;
            }
			
		} else if (eth_type == ETH_P_IPV6) {
            int l4_proto = *(unsigned char *)(packet + sizeof(struct ethhdr) + 6);
            if (l4_proto == IPPROTO_TCP) {
                payload_len = header->caplen - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr);
			    payload = (char *)packet + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
            } else if (l4_proto == IPPROTO_UDP) {
                payload_len = header->caplen - sizeof(struct ethhdr) - sizeof(struct ip6_hdr) - sizeof(struct udphdr);
                payload = (char *)packet + sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
            } else {
                continue;
            }
		}

        if (payload_len < 100) {
            continue;
        }

        memcpy(content + content_len, payload, payload_len);
        content_len += payload_len;
        pkt_cnt++;
        if (pkt_cnt == MAX_PKT_CNT) {
            break;
        }
    }

    mesa_statistical_test_suite(content, content_len, result);

    pcap_close(handle);

    return 0;
}

TEST(random_looking, telegram_mtproto_ipv4_key1)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/telegram_mtproto_ipv4_key_1.pcap", &result);

    EXPECT_EQ(result.frequency, 1);
    EXPECT_EQ(result.block_frequency, 1);
    EXPECT_EQ(result.cumulative_sums, 1);
    EXPECT_EQ(result.runs, 1);
    EXPECT_EQ(result.longest_run, 1);
    EXPECT_EQ(result.rank, 0);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 1);
    EXPECT_EQ(result.runs_distribution, 1);
    EXPECT_EQ(result.self_correlation, 1);
    EXPECT_EQ(result.binary_derivative, 1);
}

TEST(random_looking, telegram_mtproto_ipv4_key2)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/telegram_mtproto_ipv4_key_2_dd.pcap", &result);

    EXPECT_EQ(result.frequency, 1);
    EXPECT_EQ(result.block_frequency, 1);
    EXPECT_EQ(result.cumulative_sums, 1);
    EXPECT_EQ(result.runs, 1);
    EXPECT_EQ(result.longest_run, 1);
    EXPECT_EQ(result.rank, 0);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 1);
    EXPECT_EQ(result.runs_distribution, 1);
    EXPECT_EQ(result.self_correlation, 1);
    EXPECT_EQ(result.binary_derivative, 1);
}

TEST(random_looking, telegram_mtproto_ipv4_key3)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/telegram_mtproto_ipv4_key_3_ee.pcap", &result);

    EXPECT_EQ(result.frequency, 1);
    EXPECT_EQ(result.block_frequency, 0);
    EXPECT_EQ(result.cumulative_sums, 1);
    EXPECT_EQ(result.runs, 0);
    EXPECT_EQ(result.longest_run, 1);
    EXPECT_EQ(result.rank, 0);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 0);
    EXPECT_EQ(result.runs_distribution, 1);
    EXPECT_EQ(result.self_correlation, 1);
    EXPECT_EQ(result.binary_derivative, 1);
}

TEST(random_looking, telegram_mtproto_ipv6_key1)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/telegram_mtproto_ipv6_key_1.pcap", &result);

    EXPECT_EQ(result.frequency, 1);
    EXPECT_EQ(result.block_frequency, 1);
    EXPECT_EQ(result.cumulative_sums, 1);
    EXPECT_EQ(result.runs, 1);
    EXPECT_EQ(result.longest_run, 1);
    EXPECT_EQ(result.rank, 0);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 1);
    EXPECT_EQ(result.runs_distribution, 1);
    EXPECT_EQ(result.self_correlation, 1);
    EXPECT_EQ(result.binary_derivative, 1);
}

TEST(random_looking, telegram_mtproto_ipv6_key2)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/telegram_mtproto_ipv6_key_2_dd.pcap", &result);

    EXPECT_EQ(result.frequency, 1);
    EXPECT_EQ(result.block_frequency, 1);
    EXPECT_EQ(result.cumulative_sums, 1);
    EXPECT_EQ(result.runs, 1);
    EXPECT_EQ(result.longest_run, 1);
    EXPECT_EQ(result.rank, 0);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 1);
    EXPECT_EQ(result.runs_distribution, 1);
    EXPECT_EQ(result.self_correlation, 1);
    EXPECT_EQ(result.binary_derivative, 1);
}

TEST(random_looking, telegram_mtproto_ipv6_key3)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/telegram_mtproto_ipv6_key_3_ee.pcap", &result);

    EXPECT_EQ(result.frequency, 1);
    EXPECT_EQ(result.block_frequency, 0);
    EXPECT_EQ(result.cumulative_sums, 1);
    EXPECT_EQ(result.runs, 1);
    EXPECT_EQ(result.longest_run, 1);
    EXPECT_EQ(result.rank, 0);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 0);
    EXPECT_EQ(result.runs_distribution, 1);
    EXPECT_EQ(result.self_correlation, 1);
    EXPECT_EQ(result.binary_derivative, 1);
}

TEST(non_random_looking, wechat_voice_call)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/202202161604_win_wifi_30M_pure_wechat_wechat3.5.0.46_voice-call_120s_2_multinat.pcap", &result);

    EXPECT_EQ(result.frequency, 0);
    EXPECT_EQ(result.block_frequency, 1);
    EXPECT_EQ(result.cumulative_sums, 0);
    EXPECT_EQ(result.runs, 0);
    EXPECT_EQ(result.longest_run, 0);
    EXPECT_EQ(result.rank, 0);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 1);
    EXPECT_EQ(result.runs_distribution, 0);
    EXPECT_EQ(result.self_correlation, 0);
    EXPECT_EQ(result.binary_derivative, 1);
}

TEST(non_random_looking, http)
{
    struct sts_result result;
    read_pcap_and_judge_randomness("pcap/xingongsuo_kouling_http_C2S.pcap", &result);

    EXPECT_EQ(result.frequency, 0);
    EXPECT_EQ(result.block_frequency, 0);
    EXPECT_EQ(result.cumulative_sums, 0);
    EXPECT_EQ(result.runs, 1);
    EXPECT_EQ(result.longest_run, 0);
    EXPECT_EQ(result.rank, 1);
    EXPECT_EQ(result.non_overlapping_template_matching, 0);
    EXPECT_EQ(result.overlapping_template_matching, 1);
    EXPECT_EQ(result.universal, 0);
    EXPECT_EQ(result.random_excursions, 1);
    EXPECT_EQ(result.random_excursions_variant, 1);
    EXPECT_EQ(result.poker_detect, 0);
    EXPECT_EQ(result.runs_distribution, 0);
    EXPECT_EQ(result.self_correlation, 0);
    EXPECT_EQ(result.binary_derivative, 1);
}

int main(int argc, char **argv) 
{
    testing::InitGoogleTest(&argc, argv);
    //testing::GTEST_FLAG(filter) = "random_looking.telegram_mtproto_ipv6_key1";
    return RUN_ALL_TESTS();
}