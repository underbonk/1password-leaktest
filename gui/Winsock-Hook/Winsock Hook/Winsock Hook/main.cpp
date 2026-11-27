#include "Util\Research.h"
#include <string>
#include <iostream>
#include "MinHook\MinHook.h"
#include "Util\Common.h"
#include "Util\Packet.h"
#include "Util\Hook.h"
#include "Util\Stats.h"
#include <mutex>

#pragma comment(lib, "Ws2_32.lib")

#if defined _M_X64
  #ifdef _DEBUG
    #pragma comment(lib, "libMinHook-x64-v141-mdd.lib")
  #else
    #pragma comment(lib, "libMinHook-x64-v141-md.lib")
  #endif
#elif defined _M_IX86
  #ifdef _DEBUG
    #pragma comment(lib, "libMinHook-x86-v141-mdd.lib")
  #else
    #pragma comment(lib, "libMinHook-x86-v141-md.lib")
  #endif
#endif



void EjectDLL(HMODULE hModule)
{
	Sleep(500);
	FreeConsole();
	FreeLibraryAndExitThread(hModule, EXIT_SUCCESS);
};

int DisableHooks() {
	if (MH_DisableHook(MH_ALL_HOOKS) != MH_OK)
	{
		return 1;
	}

	// Uninitialize MinHook.
	if (MH_Uninitialize() != MH_OK)
	{
		return 1;
	}
	return 0;
}

// Optional initial toggle states: winsock-hook.ini next to the DLL.
// [log] send=0/1 recv=0/1 sendto=0/1 research=0/1 keywatch=0/1
static void LoadInitialToggles()
{
	char dllPath[MAX_PATH] = { 0 };
	if (!GetModuleFileNameA(util::GetCurrentModule(), dllPath, MAX_PATH))
		return;
	std::string ini = dllPath;
	size_t slash = ini.find_last_of("\\/");
	if (slash == std::string::npos)
		return;
	ini = ini.substr(0, slash + 1) + "winsock-hook.ini";

	bLogSend = GetPrivateProfileIntA("log", "send", bLogSend ? 1 : 0, ini.c_str()) != 0;
	bLogRecv = GetPrivateProfileIntA("log", "recv", bLogRecv ? 1 : 0, ini.c_str()) != 0;
	bLogSendto = GetPrivateProfileIntA("log", "sendto", bLogSendto ? 1 : 0, ini.c_str()) != 0;
	bLogResearch = GetPrivateProfileIntA("log", "research", bLogResearch ? 1 : 0, ini.c_str()) != 0;
	bKeyWatch = GetPrivateProfileIntA("log", "keywatch", bKeyWatch ? 1 : 0, ini.c_str()) != 0;
}

static void PrintLegend()
{
	printf("==================================================================\n");
	printf(" 1Password traffic viewer - educational build\n");
	printf("------------------------------------------------------------------\n");
	printf("  [L1 SESSION-BODY]  request body before/after session encryption\n");
	printf("                     (this is what the 1Password server can read)\n");
	printf("  [L2 HTTP/2]        HTTP/2 request bytes before TLS\n");
	printf("  [L3 TLS-OUT/IN]    TLS records at the Winsock layer (ciphertext,\n");
	printf("                     this is what leaves the machine)\n");
	printf("------------------------------------------------------------------\n");
	printf("  F1 send/WSASend log: %s | F2 recv log: %s | F3 sendto log: %s\n", bLogSend ? "on " : "off", bLogRecv ? "on" : "off", bLogSendto ? "on " : "off");
	printf("  F4 research L1/L2 log: %s | F5 key-shape watch: %s\n", bLogResearch ? "on" : "off", bKeyWatch ? "on" : "off");
	printf("------------------------------------------------------------------\n");
	printf("  Title bar = live counters. Coverage invariant:\n");
	printf("  every wire envelope must MATCH one L1 seal (env == matched).\n");
	printf("  UNMATCHED > 0 means an encryption path we did not hook.\n");
	printf("  (seals also fire for LOCAL vault encryption; GETs and plain\n");
	printf("  JSON POSTs are not session-encrypted, so reqs != seals.)\n");
	printf("  Full output also appended to %%TEMP%%\\1password-leaktest\\winsock-hook.log\n");
	printf("==================================================================\n");
	util::Log("---- viewer injected ----\n");
	stats::Touch();
}

DWORD WINAPI HookThread(LPVOID lpModule)
{
	util::CreateConsole();
	LoadInitialToggles();
	// Initialize MinHook.
	if (MH_Initialize() != MH_OK)
		util::Log("MH_Initialize failed");

	// Create a hook for Ws2_32.send
	if (MH_CreateHookApi(L"Ws2_32", "send", MySend, (LPVOID *)&psend) != MH_OK)
		util::Log("send hook failed");

	// Create a hook for Ws2_32.sendto
	if (MH_CreateHookApi(L"Ws2_32", "sendto", MySendto, (LPVOID*)&psendto) != MH_OK)
		util::Log("sendto hook failed");

	// Create a hook for Ws2_32.recv
	if (MH_CreateHookApi(L"Ws2_32", "recv", MyRecv, (LPVOID *)&precv) != MH_OK)
		util::Log("recv hook failed");

	// Hooks for Ws2_32.WSASend / WSARecv (the APIs 1Password actually uses)
	if (MH_CreateHookApi(L"Ws2_32", "WSASend", MyWSASend, (LPVOID*)&pWSASend) != MH_OK)
		util::Log("WSASend hook failed");

	if (MH_CreateHookApi(L"Ws2_32", "WSARecv", MyWSARecv, (LPVOID*)&pWSARecv) != MH_OK)
		util::Log("WSARecv hook failed");

	// Research layer (index.node L1/L2); no-op in other processes.
	InstallResearchHooks();

	// Enable the hooks.
	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
	{
		util::Log("MH_EnableHook failed");
		return 1;
	}

	PrintLegend();
	return 0;
}

std::string GetClipboardText()
{
	// Try opening the clipboard
	if (!OpenClipboard(nullptr))
		return ""; // error

	// Get handle of clipboard object for ANSI text
	HANDLE hData = GetClipboardData(CF_TEXT);
	if (hData == nullptr)
		return ""; // error

	// Lock the handle to get the actual text pointer
	char * pszText = static_cast<char*>(GlobalLock(hData));
	if (pszText == nullptr)
		return ""; // error

	// Save text in a string class instance
	std::string text(pszText);

	// Release the lock
	GlobalUnlock(hData);

	// Release the clipboard
	CloseClipboard();

	return text;
}

int SendFromClipboard() {
	std::string data = GetClipboardText();
	std::string prefix = "0x";

	if (data.length() < 1)
	{
		return 1;
	}

	Packet* p = new Packet();

	for (unsigned int i = 0; i < data.size(); i += 3) {
		p->AddByte(std::stoi(prefix + data[i] + data[i + 1], nullptr, 0));
	}

	p->UpdatePacketSize();
	MySend(mySock, (char*)p->GetRawPacket(), p->GetRawSize(), 0);
	delete p;

	return 0;
}

DWORD WINAPI MainThread(LPVOID lpModule)
{

	while (1)
	{
		if (GetAsyncKeyState(VK_F1) & 1) {
			bLogSend = !bLogSend;
			printf("[F1 send/WSASend log - %s]\n", bLogSend ? "true" : "false");
		}
		if (GetAsyncKeyState(VK_F2) & 1) {
			bLogRecv = !bLogRecv;
			printf("[F2 recv/WSARecv log - %s]\n", bLogRecv ? "true" : "false");
		}

		if (GetAsyncKeyState(VK_F3) & 1) {
			bLogSendto = !bLogSendto;
			printf("[F3 sendto log - %s]\n", bLogSendto ? "true" : "false");
		}

		if (GetAsyncKeyState(VK_F4) & 1) {
			bLogResearch = !bLogResearch;
			printf("[F4 research L1/L2 log - %s]\n", bLogResearch ? "true" : "false");
		}

		if (GetAsyncKeyState(VK_F5) & 1) {
			bKeyWatch = !bKeyWatch;
			printf("[F5 key-shape watch - %s]\n", bKeyWatch ? "true" : "false");
		}
		if (GetAsyncKeyState(VK_F10) & 1) {
			printf("[F10 ejecting DLL]\n");
			EjectDLL(reinterpret_cast<HMODULE>(lpModule));
		}
		/*
		if (GetAsyncKeyState(VK_F8) & 1) {
			SendFromClipboard();
		}
		*/

		Sleep(10);
	}

	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD_PTR ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, 0, MainThread, hModule, NULL, NULL);
		CreateThread(NULL, 0, HookThread, hModule, NULL, NULL);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		DisableHooks();
		break;
	}
	return TRUE;
}
