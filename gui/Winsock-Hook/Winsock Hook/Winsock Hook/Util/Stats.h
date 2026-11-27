#pragma once

#include <windows.h>
#include <atomic>

// Live counters shown in the console title bar ("header bar").
//
// How to read them (coverage invariant):
//   * reqs/bodies count HTTP/2 HEADERS and DATA frames at the L2 writers.
//     GETs have no body and plain-JSON POSTs (auth start, SRP) are not
//     session-encrypted, so bodies is always <= reqs and neither equals seals.
//   * seals (L1) counts body-encryption calls, including LOCAL vault
//     encryption that never reaches the network, so seals >= env matched.
//   * The invariant that matters: every encrypted envelope seen on the wire
//     must match one L1 seal. env UNMATCHED > 0 means an encryption path we
//     did not hook (e.g. the v2 wrapper at index.node+0x5153950).
//   * env unparsed counts envelopes we failed to reassemble/extract locally;
//     it is a tooling limitation, not an alarm.
namespace stats {
extern std::atomic<unsigned long long> requests;     // L2 HEADERS frames
extern std::atomic<unsigned long long> bodies;       // L2 DATA frames
extern std::atomic<unsigned long long> tlsSends;     // L3 send/sendto/WSASend calls
extern std::atomic<unsigned long long> tlsRecvs;     // L3 recv/WSARecv with data
extern std::atomic<unsigned long long> seals;        // L1 body-seal calls
extern std::atomic<unsigned long long> envelopes;    // L2 envelopes fully reassembled
extern std::atomic<unsigned long long> envMatched;   // envelopes matched to an L1 seal
extern std::atomic<unsigned long long> envUnmatched; // envelopes with NO L1 seal (alarm)
extern std::atomic<unsigned long long> envUnparsed;  // envelopes we failed to parse
extern std::atomic<unsigned long long> keyHits;      // key-shape watcher hits
void Touch(); // refresh the console title bar
}
