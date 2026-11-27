#include "Util\Hook.h"
#include <stdio.h>
#include "Util\Common.h"
#include "Util\Stats.h"
#include <mutex>


std::mutex mtx;
bool bLogRecv = false;
bool bLogSend = false;
bool bLogSendto = false;

SOCKET mySock = 0;
int (WINAPI *precv)(SOCKET socket, char* buffer, int length, int flags) = NULL;
int (WINAPI *psend)(SOCKET socket, const char* buffer, int length, int flags) = NULL;
int (WINAPI* psendto)(SOCKET socket, const char* buffer, int length, int flags, const struct sockaddr* to, int tolen) = NULL;
int (WSAAPI* pWSASend)(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine) = NULL;
int (WSAAPI* pWSARecv)(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesRecvd, LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine) = NULL;

static void NoteSocket(SOCKET socket)
{
	if (mySock == 0) {
		util::Log("[SOCKET - %d]\n", socket);
		mySock = socket;
	}
}

static void KeyWatch(const void* buffer, size_t len, const char* layer)
{
	if (util::LooksLikeSecretKey(buffer, len))
	{
		stats::keyHits++;
		printf("  !!! SECRET-KEY-SHAPED DATA IN %s !!!\n", layer);
		util::Log("!!! SECRET-KEY-SHAPED DATA IN %s !!!\n", layer);
		stats::Touch();
	}
}

int WINAPI MyRecv(SOCKET socket, char* buffer, int length, int flags)
{
	NoteSocket(socket);

	// Fixed: recv must be logged AFTER the call fills the buffer, using the
	// returned byte count (the original logged the unfilled buffer).
	int ret = precv(socket, buffer, length, flags);
	DWORD savedError = WSAGetLastError();

	if (ret > 0) { stats::tlsRecvs++; stats::Touch(); }

	if (bLogRecv && ret > MINPACKETLEN) {
		std::lock_guard<std::mutex> guard(mtx);
		printf("[L3 TLS-IN  recv-%d:%d]\n", ret, flags);
		util::Log("[L3 TLS-IN  recv-%d:%d]\n", ret, flags);
		util::HexDump("  ", buffer, ret, 512);
	}

	SetLastError(savedError);
	return ret;
}

int WINAPI MySend(SOCKET socket, const char* buffer, int length, int flags)
{
	NoteSocket(socket);
	stats::tlsSends++; stats::Touch();

	if (bLogSend && length > MINPACKETLEN)
	{
		std::lock_guard<std::mutex> guard(mtx);
		printf("[L3 TLS-OUT send-%d:%d]\n", length, flags);
		util::Log("[L3 TLS-OUT send-%d:%d]\n", length, flags);
		util::HexDump("  ", buffer, length, 512);
		KeyWatch(buffer, length, "TLS-OUT");
	}
	return psend(socket, buffer, length, flags);
}

int WINAPI MySendto(SOCKET socket, const char* buffer, int length, int flags, const sockaddr* to, int tolen)
{
	std::lock_guard<std::mutex> guard(mtx);
	NoteSocket(socket);

	if (bLogSendto && length > 1)
	{
		printf("[L3 TLS-OUT sendto-%d:%d]\n", length, flags);
		util::Log("[L3 TLS-OUT sendto-%d:%d]\n", length, flags);
		util::HexDump("  ", buffer, length, 512);
		KeyWatch(buffer, length, "TLS-OUT");
	}

	return psendto(socket, buffer, length, flags, to, tolen);
}

int WSAAPI MyWSASend(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
	NoteSocket(socket);
	stats::tlsSends++; stats::Touch();

	if (bLogSend && buffers)
	{
		std::lock_guard<std::mutex> guard(mtx);
		for (DWORD i = 0; i < bufferCount && i < 32; i++)
		{
			if (buffers[i].len > MINPACKETLEN && buffers[i].buf)
			{
				printf("[L3 TLS-OUT WSASend-%u:%lu buf %lu]\n", flags, bufferCount, i);
				util::Log("[L3 TLS-OUT WSASend-%u:%lu buf %lu]\n", flags, bufferCount, i);
				util::HexDump("  ", buffers[i].buf, buffers[i].len, 512);
				KeyWatch(buffers[i].buf, buffers[i].len, "TLS-OUT");
			}
		}
	}
	return pWSASend(socket, buffers, bufferCount, bytesSent, flags, overlapped, completionRoutine);
}

int WSAAPI MyWSARecv(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesRecvd, LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
	NoteSocket(socket);

	int ret = pWSARecv(socket, buffers, bufferCount, bytesRecvd, flags, overlapped, completionRoutine);
	DWORD savedError = WSAGetLastError();

	if (ret == 0 && bytesRecvd && *bytesRecvd > 0) { stats::tlsRecvs++; stats::Touch(); }

	// Only immediate completions have valid buffer contents here. Overlapped
	// recvs complete later and are noted once, not captured by this hook.
	if (bLogRecv && ret == 0 && bytesRecvd && *bytesRecvd > MINPACKETLEN && buffers)
	{
		std::lock_guard<std::mutex> guard(mtx);
		DWORD remaining = *bytesRecvd;
		for (DWORD i = 0; i < bufferCount && i < 32 && remaining; i++)
		{
			DWORD chunk = buffers[i].len < remaining ? buffers[i].len : remaining;
			printf("[L3 TLS-IN  WSARecv buf %lu len %lu]\n", i, chunk);
			util::Log("[L3 TLS-IN  WSARecv buf %lu len %lu]\n", i, chunk);
			util::HexDump("  ", buffers[i].buf, chunk, 512);
			remaining -= chunk;
		}
	}

	SetLastError(savedError);
	return ret;
}
