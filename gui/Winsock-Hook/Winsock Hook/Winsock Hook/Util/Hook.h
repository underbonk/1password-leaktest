#pragma once

#include <winsock2.h>
#include <windows.h>

#define MINPACKETLEN 5

extern SOCKET mySock;
extern bool bLogRecv;
extern bool bLogSend;
extern bool bLogSendto;

// HOOKS

// winsock recv
extern int (WINAPI *precv)(SOCKET socket, char* buffer, int length, int flags);
int WINAPI MyRecv(SOCKET socket, char* buffer, int length, int flags);

// winsock send
extern int (WINAPI *psend)(SOCKET socket, const char* buffer, int length, int flags);
int WINAPI MySend(SOCKET socket, const char* buffer, int length, int flags);

// winsock sendto
extern int (WINAPI* psendto)(SOCKET socket, const char* buffer, int length, int flags, const struct sockaddr* to, int tolen);
int WINAPI MySendto(SOCKET socket, const char* buffer, int length, int flags, const sockaddr* to, int tolen);

// winsock WSASend / WSARecv (what modern clients, including 1Password, use)
extern int (WSAAPI* pWSASend)(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);
int WSAAPI MyWSASend(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);

extern int (WSAAPI* pWSARecv)(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesRecvd, LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);
int WSAAPI MyWSARecv(SOCKET socket, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesRecvd, LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine);
