// Research hooks for the 1Password Secret Key investigation.
// Build-specific: index.node, package 8.12.46.29,
// SHA-256 3ddfb31d515b3776756047236c59725202a10387cd60ddfda26ce86295c75821.
// Entry bytes are verified before every hook; a mismatch disables that hook.
// These detours are read-only: they never modify arguments or results and
// never dereference the key/context argument of the body-seal routine.
#include "Util\Research.h"
#include <stdio.h>
#include <mutex>
#include <map>
#include <deque>
#include <string>
#include <vector>
#include "MinHook\MinHook.h"
#include "Util\Common.h"
#include "Util\Stats.h"

bool bLogResearch = true;
bool bKeyWatch = true;

static std::mutex g_dumpMtx;

// ---------------------------------------------------------------------------
// SEH-safe reads. Kept in POD-only helpers: no C++ objects in scope, so these
// compile under any exception model and a bad pointer degrades to a log line.
// ---------------------------------------------------------------------------
struct VecDesc { unsigned long long cap; const unsigned char* ptr; unsigned long long len; };

static bool SafeReadDesc(const void* desc, VecDesc& out)
{
	__try {
		out.cap = *(const unsigned long long*)desc;
		out.ptr = *(const unsigned char* const*)((const char*)desc + 8);
		out.len = *(const unsigned long long*)((const char*)desc + 16);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool SafeReadSealOutput(const unsigned char* out, unsigned long long& ctLen, const unsigned char*& ct)
{
	__try {
		if (out[0] != 0) return false;  // non-zero status = encryption failed
		ctLen = *(const unsigned long long*)(out + 40);
		ct = *(const unsigned char* const*)(out + 32);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool EntryBytesMatch(const unsigned char* addr, const unsigned char* sig, size_t sigLen)
{
	__try { return memcmp(addr, sig, sigLen) == 0; }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void KeyWatch(const char* layer, const void* data, size_t len)
{
	if (bKeyWatch && util::LooksLikeSecretKey(data, len))
	{
		stats::keyHits++;
		printf("  !!! SECRET-KEY-SHAPED DATA IN %s !!!\n", layer);
		util::Log("!!! SECRET-KEY-SHAPED DATA IN %s !!!\n", layer);
		stats::Touch();
	}
}

// ---------------------------------------------------------------------------
// Live coverage accounting.
//
// The L2 writers hand us raw HTTP/2 bytes. Frames routinely span buffers (a
// DATA frame's payload continues into the next segment), so we walk frames
// with per-connection state instead of assuming buffer == frame.
//
// Envelope matching: an L1 seal stores (12-byte nonce, ciphertext+tag). An
// envelope on the wire carries base64url(iv)=nonce and base64url(data)=ct.
// envelopes must equal matched+unmatched(+unparsed). UNMATCHED>0 = alarm.
// ---------------------------------------------------------------------------
struct ConnState {
	unsigned char hdr[9];
	int hdrHave;
	unsigned long long payloadRem;
	int payloadSid;
	bool payloadIsData;
	ConnState() : hdrHave(0), payloadRem(0), payloadSid(0), payloadIsData(false) {}
};

struct SealRec { std::string nonce; std::string ct; bool matched; };

static std::map<void*, ConnState> g_conns;
static std::map<std::pair<void*, int>, std::string> g_json;
static std::deque<SealRec> g_seals;

static bool SafeReadNonce(const void* nonce, unsigned char out12[12])
{
	__try { memcpy(out12, nonce, 12); return true; }
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static std::string B64UrlDecode(const std::string& in)
{
	static const signed char T[256] = { 0 };
	std::string out;
	int val = 0, bits = -8;
	for (char ch : in)
	{
		unsigned char c = (unsigned char)ch;
		int d;
		if (c >= 'A' && c <= 'Z') d = c - 'A';
		else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
		else if (c >= '0' && c <= '9') d = c - '0' + 52;
		else if (c == '-') d = 62;
		else if (c == '_') d = 63;
		else if (c == '+') d = 62;
		else if (c == '/') d = 63;
		else continue; // skip padding/whitespace
		val = (val << 6) | d;
		bits += 6;
		if (bits >= 0) { out += (char)((val >> bits) & 0xFF); bits -= 8; }
	}
	return out;
}

static bool ExtractJsonField(const std::string& j, const char* field, std::string& value)
{
	std::string needle = std::string("\"") + field + "\":\"";
	size_t at = j.find(needle);
	if (at == std::string::npos) return false;
	at += needle.size();
	size_t end = j.find('"', at);
	if (end == std::string::npos) return false;
	value = j.substr(at, end - at);
	return true;
}

static void FinalizeJson(void* stream, int sid)
{
	auto it = g_json.find(std::make_pair(stream, sid));
	if (it == g_json.end()) return;
	std::string j = it->second;
	g_json.erase(it);

	if (j.find("\"cty\"") == std::string::npos)
		return; // a DATA frame that is not an envelope: plain JSON body, counted already

	stats::envelopes++;
	std::string iv, data;
	if (!ExtractJsonField(j, "iv", iv) || !ExtractJsonField(j, "data", data))
	{
		stats::envUnparsed++;
		printf("[stats] envelope on stream %d could not be fully parsed (counted as unparsed, not unmatched)\n", sid);
		util::Log("[stats] envelope unparsed on stream %d\n", sid);
		stats::Touch();
		return;
	}
	std::string nonce = B64UrlDecode(iv);
	std::string ct = B64UrlDecode(data);
	for (auto& rec : g_seals)
	{
		if (!rec.matched && rec.nonce == nonce && rec.ct == ct)
		{
			rec.matched = true;
			stats::envMatched++;
			printf("[stats] envelope on stream %d MATCHED an L1 seal (plaintext was observed)\n", sid);
			util::Log("[stats] envelope stream %d matched L1\n", sid);
			stats::Touch();
			return;
		}
	}
	stats::envUnmatched++;
	printf("[stats] !!! envelope on stream %d did NOT match any L1 seal - possible unhooked encryption path !!!\n", sid);
	util::Log("[stats] !!! envelope stream %d UNMATCHED !!!\n", sid);
	stats::Touch();
}

static void AppendJson(void* stream, int sid, const unsigned char* p, size_t len)
{
	std::string& j = g_json[std::make_pair(stream, sid)];
	if (j.size() < 262144)
		j.append((const char*)p, len);
}

// HTTP/2 frame walker with cross-buffer state. Counts HEADERS/DATA frames and
// feeds DATA payloads of JSON bodies to the envelope matcher.
static void ProcessBuffer(void* stream, const unsigned char* p, size_t len)
{
	if (!p || !len) return;
	ConnState& c = g_conns[stream];
	size_t off = 0;

	// Client connection preface arrives as its own first write.
	if (c.hdrHave == 0 && c.payloadRem == 0 && len >= 24 &&
		memcmp(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) == 0)
		off = 24;

	while (off < len)
	{
		if (c.payloadRem > 0)
		{
			size_t take = (size_t)((len - off) < c.payloadRem ? (len - off) : c.payloadRem);
			if (c.payloadIsData) AppendJson(stream, c.payloadSid, p + off, take);
			c.payloadRem -= take;
			off += take;
			if (c.payloadRem == 0 && c.payloadIsData) FinalizeJson(stream, c.payloadSid);
			continue;
		}
		while (off < len && c.hdrHave < 9)
			c.hdr[c.hdrHave++] = p[off++];
		if (c.hdrHave < 9) break;

		unsigned long long flen = ((unsigned long long)c.hdr[0] << 16) | ((unsigned long long)c.hdr[1] << 8) | c.hdr[2];
		int type = c.hdr[3];
		int sid = (((int)c.hdr[5] << 24) | ((int)c.hdr[6] << 16) | ((int)c.hdr[7] << 8) | c.hdr[8]) & 0x7fffffff;
		c.hdrHave = 0;

		if (type == 0x1) stats::requests++;
		if (type == 0x0) stats::bodies++;
		if (flen > 0 && flen <= 16 * 1024 * 1024)
		{
			c.payloadRem = flen;
			c.payloadSid = sid;
			c.payloadIsData = (type == 0x0);
		}
		stats::Touch();
	}

	// Bound the maps; connections are short-lived in this client.
	if (g_conns.size() > 128) g_conns.erase(g_conns.begin());
	if (g_json.size() > 128) g_json.erase(g_json.begin());
}

// POD wrapper so SEH protection is legal around the C++ walker.
static void SafeProcessBuffer(void* stream, const unsigned char* p, size_t len)
{
	__try { ProcessBuffer(stream, p, len); }
	__except (EXCEPTION_EXECUTE_HANDLER) { }
}

// ---------------------------------------------------------------------------
// [L1] JSON-envelope request-body encryption wrapper, index.node RVA 0x5F25440.
// Inferred ABI (Windows x64): RCX = output, RDX = key/context (NEVER read),
// R8 = body vector descriptor {cap +0, ptr +8, len +16}, R9 = 12-byte nonce.
// Encryption is in place, so the plaintext is dumped BEFORE the original runs.
// Success output: byte +0 = 0, nonce +1 (12B), capacity +24, ct ptr +32,
// ct+tag len +40.
// ---------------------------------------------------------------------------
typedef void(__fastcall* BodySeal_t)(unsigned char* out, void* ctx, void* desc, void* nonce);
static BodySeal_t oBodySeal = NULL;

static void __fastcall MyBodySeal(unsigned char* out, void* ctx, void* desc, void* nonce)
{
	VecDesc v = { 0, NULL, 0 };
	bool readable = SafeReadDesc(desc, v);
	bool sane = readable && v.ptr && v.len > 0 && v.len <= v.cap && v.cap <= 16 * 1024 * 1024;

	if (bLogResearch)
	{
		std::lock_guard<std::mutex> guard(g_dumpMtx);
		if (sane)
		{
			printf("[L1 SESSION-BODY] encrypt request body, plaintext %llu bytes:\n", v.len);
			util::Log("[L1 SESSION-BODY] plaintext %llu bytes:\n", v.len);
			util::HexDump("  ", v.ptr, (size_t)v.len, 1024);
			KeyWatch("SESSION-BODY PLAINTEXT", v.ptr, (size_t)v.len);
		}
		else
		{
			printf("[L1 SESSION-BODY] called with unreadable/insane descriptor\n");
			util::Log("[L1 SESSION-BODY] unreadable descriptor\n");
		}
	}

	oBodySeal(out, ctx, desc, nonce);

	unsigned long long ctLen = 0; const unsigned char* ct = NULL;
	unsigned char nonce12[12] = { 0 };
	bool haveNonce = SafeReadNonce(nonce, nonce12);
	if (SafeReadSealOutput(out, ctLen, ct) && ct && ctLen > 0 && ctLen <= 16 * 1024 * 1024)
	{
		{
			std::lock_guard<std::mutex> guard(g_dumpMtx);
			stats::seals++;
			if (haveNonce)
			{
				SealRec rec;
				rec.nonce.assign((const char*)nonce12, 12);
				rec.ct.assign((const char*)ct, (size_t)ctLen);
				rec.matched = false;
				g_seals.push_back(rec);
				if (g_seals.size() > 256) g_seals.pop_front();
			}
			if (bLogResearch)
			{
				printf("[L1 SESSION-BODY] -> ciphertext+tag %llu bytes (this is what the server can decrypt):\n", ctLen);
				util::Log("[L1 SESSION-BODY] ciphertext+tag %llu bytes:\n", ctLen);
				util::HexDump("  ", ct, (size_t)ctLen, 256);
			}
			stats::Touch();
		}
	}
}

// ---------------------------------------------------------------------------
// [L2] Native HTTP/2 writers (pre-TLS). Scalar: RVA 0x614CBF0, buffer in arg3
// (R8), length in arg4 (R9). Vectored: RVA 0x6150780, arg3 points to 16-byte
// descriptors {DWORD len at +0, ptr at +8}, arg4 = count.
// ---------------------------------------------------------------------------
typedef void(__fastcall* ScalarWrite_t)(void* stream, void* unk, const unsigned char* buf, unsigned long long len);
static ScalarWrite_t oScalarWrite = NULL;

static void __fastcall MyScalarWrite(void* stream, void* unk, const unsigned char* buf, unsigned long long len)
{
	if (buf && len > 0 && len <= 1024 * 1024)
	{
		std::lock_guard<std::mutex> guard(g_dumpMtx);
		SafeProcessBuffer(stream, buf, (size_t)len);
		if (bLogResearch)
		{
			printf("[L2 HTTP/2 scalar] %llu bytes before TLS:\n", len);
			util::Log("[L2 HTTP/2 scalar] %llu bytes:\n", len);
			util::HexDump("  ", buf, (size_t)len, 1024);
			KeyWatch("HTTP/2 PLAINTEXT", buf, (size_t)len);
		}
	}
	oScalarWrite(stream, unk, buf, len);
}

typedef void(__fastcall* VectorWrite_t)(void* stream, void* unk, const unsigned char* iov, unsigned int count);
static VectorWrite_t oVectorWrite = NULL;

// POD-only helper (no C++ objects in scope) so SEH is legal here.
static void DumpSegments(void* stream, const unsigned char* iov, unsigned int count)
{
	__try {
		for (unsigned int i = 0; i < count; i++)
		{
			unsigned int segLen = *(const unsigned int*)(iov + (size_t)i * 16);
			const unsigned char* segPtr = *(const unsigned char* const*)(iov + (size_t)i * 16 + 8);
			if (segPtr && segLen > 0 && segLen <= 1024 * 1024)
			{
				SafeProcessBuffer(stream, segPtr, segLen);
				if (bLogResearch)
				{
					printf("  segment %u, %u bytes:\n", i, segLen);
					util::Log("  segment %u, %u bytes:\n", i, segLen);
					util::HexDump("    ", segPtr, segLen, 1024);
					KeyWatch("HTTP/2 PLAINTEXT", segPtr, segLen);
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("  (segment read fault)\n");
		util::Log("  (segment read fault)\n");
	}
}

static void __fastcall MyVectorWrite(void* stream, void* unk, const unsigned char* iov, unsigned int count)
{
	if (iov && count > 0 && count <= 1024)
	{
		std::lock_guard<std::mutex> guard(g_dumpMtx);
		if (bLogResearch)
		{
			printf("[L2 HTTP/2 vectored] %u segment(s) before TLS:\n", count);
			util::Log("[L2 HTTP/2 vectored] %u segment(s):\n", count);
		}
		DumpSegments(stream, iov, count);
	}
	oVectorWrite(stream, unk, iov, count);
}

// ---------------------------------------------------------------------------
// Installation with entry-signature verification.
// ---------------------------------------------------------------------------
struct HookSpec {
	const char* name;
	unsigned long long rva;
	const unsigned char* sig;
	size_t sigLen;
	void* detour;
	void* original;
};

static const unsigned char SIG_BODYSEAL[] = { 0x55,0x41,0x57,0x41,0x56,0x41,0x54,0x56,0x57,0x53,0x48,0x81,0xEC,0x80,0x00,0x00 };
static const unsigned char SIG_SCALAR[]   = { 0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x55,0x53,0x48,0x83,0xEC,0x58 };
static const unsigned char SIG_VECTOR[]   = { 0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x56,0x57,0x55,0x53,0x48,0x83,0xEC,0x48 };

bool InstallResearchHooks()
{
	HMODULE mod = GetModuleHandleA("index.node");
	if (!mod)
	{
		printf("[research] index.node not loaded in this process; L1/L2 layers inactive (Winsock layer still works)\n");
		util::Log("[research] index.node not loaded; L1/L2 inactive\n");
		return false;
	}

	const unsigned char* base = (const unsigned char*)mod;
	HookSpec specs[] = {
		{ "L1 body-seal 0x5F25440",  0x5F25440, SIG_BODYSEAL, sizeof(SIG_BODYSEAL), &MyBodySeal,    &oBodySeal },
		{ "L2 scalar-writer 0x614CBF0", 0x614CBF0, SIG_SCALAR, sizeof(SIG_SCALAR),  &MyScalarWrite, &oScalarWrite },
		{ "L2 vectored-writer 0x6150780", 0x6150780, SIG_VECTOR, sizeof(SIG_VECTOR), &MyVectorWrite, &oVectorWrite },
	};

	bool any = false;
	for (int i = 0; i < 3; i++)
	{
		HookSpec& s = specs[i];
		const unsigned char* target = base + s.rva;
		if (!EntryBytesMatch(target, s.sig, s.sigLen))
		{
			printf("[research] SIGNATURE MISMATCH at %s - hook disabled (wrong build?)\n", s.name);
			util::Log("[research] SIGNATURE MISMATCH at %s - disabled\n", s.name);
			continue;
		}
		if (MH_CreateHook((LPVOID)target, s.detour, (LPVOID*)s.original) != MH_OK)
		{
			printf("[research] MH_CreateHook failed at %s\n", s.name);
			util::Log("[research] MH_CreateHook failed at %s\n", s.name);
			continue;
		}
		printf("[research] signature OK, hook created: %s\n", s.name);
		util::Log("[research] hook created: %s\n", s.name);
		any = true;
	}
	return any;
}
