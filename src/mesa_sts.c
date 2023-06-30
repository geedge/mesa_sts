#include <stdlib.h>
#include "include/utilities.h"
#include "include/stat_fncs.h"
#include "mesa_sts.h"

int mesa_statistical_test_suite(void* data,unsigned int datalen, struct sts_result* result)
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
	result->frequency = Frequency(tp.n,epsilon);
	result->block_frequency = BlockFrequency(tp.blockFrequencyBlockLength, tp.n,epsilon);
	result->cumulative_sums =  CumulativeSums(tp.n,epsilon);
	result->runs = Runs(tp.n,epsilon);
	result->longest_run = LongestRunOfOnes(tp.n,epsilon);
	result->rank = Rank(tp.n,epsilon);
	//result->discrete_fourier_transform = DiscreteFourierTransform(tp.n,epsilon);//cost too much time
	result->non_overlapping_template_matching = NonOverlappingTemplateMatchings(tp.nonOverlappingTemplateBlockLength, tp.n,epsilon);
	result->overlapping_template_matching = OverlappingTemplateMatchings(tp.overlappingTemplateBlockLength, tp.n,epsilon);
	result->universal = Universal(tp.n,epsilon);
	//result->approximate_entropy = ApproximateEntropy(tp.approximateEntropyBlockLength, tp.n,epsilon);//cost too much time
	result->random_excursions = RandomExcursions(tp.n,epsilon);
	result->random_excursions_variant = RandomExcursionsVariant(tp.n,epsilon);
	//result->serial = Serial(tp.serialBlockLength,tp.n,epsilon);//cost too much time
	//sresult->linear_complexity = LinearComplexity(tp.linearComplexitySequenceLength, tp.n,epsilon);//cost too much time
	result->poker_detect = PokerDetect(tp.PokerDetectMLength,tp.n,epsilon);
	result->runs_distribution = RunsDistribution(tp.n,epsilon);
	result->self_correlation = SelfCorrelation(tp.SelfCorrelationDLength,tp.n,epsilon);
    result->binary_derivative = BinaryDerivate(tp.BinaryDerivateKLength,tp.n,epsilon,tp.n);//this function will change the value of epsilon, must be the last one

	free(epsilon);
	epsilon = NULL;

	return 0;
}