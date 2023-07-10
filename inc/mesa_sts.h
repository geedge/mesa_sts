#ifndef _MESA_STS_H_
#define _MESA_STS_H_

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

int mesa_statistical_test_suite(void* data,unsigned int datalen, struct sts_result* result);

#ifdef __cplusplus
}
#endif

#endif /*  _MESA_STS_H_  */