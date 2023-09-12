#ifndef _MESA_STS_H_
#define _MESA_STS_H_

#define STS_RANDOM_JUDGE_NUM 15

#define STS_SET_FLAG(flag, idx) (flag |= (1 << idx))
#define STS_TEST_FLAG(flag, idx) (flag & (1 << idx))

enum sts_random_judge_list_idx
{
	STS_FREQUENCY = 0,
	STS_BLOCK_FREQUENCY,
	STS_CUMULATIVE_SUMS,
	STS_RUNS,
	STS_LONGEST_RUN,
	STS_RANK,
	STS_NON_OVERLAPPING_TEMPLATE_MATCHING,
	STS_OVERLAPPING_TEMPLATE_MATCHING,
	STS_UNIVERSAL,
	STS_RANDOM_EXCURSIONS,
	STS_RANDOM_EXCURSIONS_VARIANT,
	STS_POKER_DETECT,
	STS_RUNS_DISTRIBUTION,
	STS_SELF_CORRELATION,
	STS_BINARY_DERIVATE,
	STS_RANDOM_IDX_MAX
};

struct sts_result {
	unsigned char frequency;
	unsigned char block_frequency;
	unsigned char cumulative_sums;
	unsigned char runs;
	unsigned char longest_run;
	unsigned char rank;
	unsigned char non_overlapping_template_matching;
	unsigned char overlapping_template_matching;
	unsigned char universal;
	unsigned char random_excursions;
	unsigned char random_excursions_variant;
	unsigned char poker_detect;
	unsigned char runs_distribution;
	unsigned char self_correlation;
	unsigned char binary_derivative;
};

#ifdef __cplusplus
extern "C" {
#endif

int mesa_statistical_test_suite(void* data,unsigned int datalen, struct sts_result* result, unsigned int random_judge_switch_flag);

#ifdef __cplusplus
}
#endif

#endif /*  _MESA_STS_H_  */
