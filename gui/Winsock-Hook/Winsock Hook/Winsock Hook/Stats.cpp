#include "Util\Stats.h"
#include <stdio.h>

std::atomic<unsigned long long> stats::requests(0);
std::atomic<unsigned long long> stats::bodies(0);
std::atomic<unsigned long long> stats::tlsSends(0);
std::atomic<unsigned long long> stats::tlsRecvs(0);
std::atomic<unsigned long long> stats::seals(0);
std::atomic<unsigned long long> stats::envelopes(0);
std::atomic<unsigned long long> stats::envMatched(0);
std::atomic<unsigned long long> stats::envUnmatched(0);
std::atomic<unsigned long long> stats::envUnparsed(0);
std::atomic<unsigned long long> stats::keyHits(0);

void stats::Touch()
{
	char title[260];
	sprintf_s(title,
		"1P viewer | reqs %llu | bodies %llu | TLS out/in %llu/%llu | L1 seals %llu | env %llu = matched %llu + UNMATCHED %llu (+unparsed %llu) | key-hits %llu",
		requests.load(), bodies.load(), tlsSends.load(), tlsRecvs.load(), seals.load(),
		envelopes.load(), envMatched.load(), envUnmatched.load(), envUnparsed.load(), keyHits.load());
	SetConsoleTitleA(title);
}
