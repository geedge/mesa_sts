#include <stdlib.h>
#include "include/utilities.h"
#include "include/stat_fncs.h"
#include "mesa_sts.h"

int mesa_statistical_test_suite(void* data,unsigned int datalen, struct sts_result* result, unsigned int random_judge_switch_flag)
{
	TP tp;
	tp.n = datalen;
	tp.blockFrequencyBlockLength = 128;
	tp.nonOverlappingTemplateBlockLength = 9;
	tp.overlappingTemplateBlockLength = 9;
	tp.approximateEntropyBlockLength = 10;
	tp.serialBlockLength = 16;
	tp.linearComplexitySequenceLength = 500;
	tp.numOfBitStreams = 1;
	tp.PokerDetectMLength = 8;
	tp.BinaryDerivateKLength = 3;
	tp.SelfCorrelationDLength = 8;

	BitSequence* epsilon = (BitSequence *)calloc(tp.n,sizeof(BitSequence));
	int	done, num_0s, num_1s, bitsRead;
	num_0s = 0;
	num_1s = 0;
	bitsRead = 0;
	done = 0;
	done = convertToBits((BYTE*)data,datalen,tp.n,&num_0s,&num_1s,&bitsRead,epsilon);
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_FREQUENCY))
	{
		result->frequency = Frequency(tp.n,epsilon);
	}

	if (STS_TEST_FLAG(random_judge_switch_flag, STS_BLOCK_FREQUENCY))
	{
		result->block_frequency = BlockFrequency(tp.blockFrequencyBlockLength, tp.n,epsilon);
	}

	if (STS_TEST_FLAG(random_judge_switch_flag, STS_CUMULATIVE_SUMS))
	{
		result->cumulative_sums =  CumulativeSums(tp.n,epsilon);
	}

	if (STS_TEST_FLAG(random_judge_switch_flag, STS_RUNS))
	{
		result->runs = Runs(tp.n,epsilon);
	}

	if (STS_TEST_FLAG(random_judge_switch_flag, STS_LONGEST_RUN))
	{
		result->longest_run = LongestRunOfOnes(tp.n,epsilon);
	}
	
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_RANK))
	{
		result->rank = Rank(tp.n,epsilon);
	}
	
	//result->discrete_fourier_transform = DiscreteFourierTransform(tp.n,epsilon);//cost too much time

	if (STS_TEST_FLAG(random_judge_switch_flag, STS_NON_OVERLAPPING_TEMPLATE_MATCHING))
	{
		result->non_overlapping_template_matching = NonOverlappingTemplateMatchings(tp.nonOverlappingTemplateBlockLength, tp.n,epsilon);
	}
	
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_OVERLAPPING_TEMPLATE_MATCHING))
	{
		result->overlapping_template_matching = OverlappingTemplateMatchings(tp.overlappingTemplateBlockLength, tp.n,epsilon);
	}
	
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_UNIVERSAL))
	{
		result->universal = Universal(tp.n,epsilon);
	}
	
	//result->approximate_entropy = ApproximateEntropy(tp.approximateEntropyBlockLength, tp.n,epsilon);//cost too much time

	if (STS_TEST_FLAG(random_judge_switch_flag, STS_RANDOM_EXCURSIONS))
	{
		result->random_excursions = RandomExcursions(tp.n,epsilon);
	}
	
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_RANDOM_EXCURSIONS_VARIANT))
	{
		result->random_excursions_variant = RandomExcursionsVariant(tp.n,epsilon);
	}
	
	//result->serial = Serial(tp.serialBlockLength,tp.n,epsilon);//cost too much time
	//sresult->linear_complexity = LinearComplexity(tp.linearComplexitySequenceLength, tp.n,epsilon);//cost too much time

	if (STS_TEST_FLAG(random_judge_switch_flag, STS_POKER_DETECT))
	{
		result->poker_detect = PokerDetect(tp.PokerDetectMLength,tp.n,epsilon);
	}
	
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_RUNS_DISTRIBUTION))
	{
		result->runs_distribution = RunsDistribution(tp.n,epsilon);
	}
	
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_SELF_CORRELATION))
	{
		result->self_correlation = SelfCorrelation(tp.SelfCorrelationDLength,tp.n,epsilon);
	}
	
	if (STS_TEST_FLAG(random_judge_switch_flag, STS_BINARY_DERIVATE))
	{
		result->binary_derivative = BinaryDerivate(tp.BinaryDerivateKLength,tp.n,epsilon,tp.n);//this function will change the value of epsilon, must be the last one
	}

	free(epsilon);
	epsilon = NULL;

	return 0;
}