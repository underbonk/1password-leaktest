#include <windows.h>
#include <fcntl.h>
#include <stdio.h>
#include <io.h>
#include <string>
#include <fstream>
#include <commdlg.h>

#include "Util\Common.h"

// Log beside the researcher's temp directory. The DLL never writes the
// Secret Key on its own; this file receives the same hex lines as the console.
#define LOGFILE_PATH_REL "1password-leaktest\\winsock-hook.log"

void util::CreateConsole()
{
	if (!AllocConsole())
	{
		// Target already has a console (or none can be allocated): keep
		// running silently, output still goes to the log file.
		util::Log("AllocConsole failed, gle=%d; logging to file only\n", GetLastError());
		return;
	}

	auto lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	auto hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
	auto fp = _fdopen(hConHandle, "w");

	freopen_s(&fp, "CONOUT$", "w", stdout);

	*stdout = *fp;
	setvbuf(stdout, NULL, _IONBF, 0);
}

HMODULE util::GetCurrentModule()
{
	HMODULE hModule = NULL;

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCTSTR>(GetCurrentModule),
		&hModule);

	return hModule;
}

void util::Log(const char *fmt, ...)
{
	if (!fmt)	return;

	char		text[4096];
	va_list		ap;
	va_start(ap, fmt);
	vsprintf_s(text, fmt, ap);
	va_end(ap);

	char dir[MAX_PATH];
	GetTempPathA(MAX_PATH, dir);
	std::string path = std::string(dir) + LOGFILE_PATH_REL;
	CreateDirectoryA((std::string(dir) + "1password-leaktest").c_str(), NULL);
	std::ofstream logfile(path.c_str(), std::ios::app);
	if (logfile.is_open() && text) {
		logfile << text;
	}
	logfile.close();
}

void util::HexDump(const char* tag, const void* data, size_t len, size_t maxConsole)
{
	const unsigned char* p = (const unsigned char*)data;
	size_t shown = len;
	bool truncated = false;
	if (maxConsole && shown > maxConsole) { shown = maxConsole; truncated = true; }

	for (size_t off = 0; off < shown; off += 16)
	{
		char line[160];
		int n = 0;
		n += sprintf_s(line + n, sizeof(line) - n, "%s%08X  ", tag ? tag : "", (unsigned int)off);
		for (size_t i = 0; i < 16; i++)
		{
			if (off + i < shown)
				n += sprintf_s(line + n, sizeof(line) - n, "%02X ", p[off + i]);
			else
				n += sprintf_s(line + n, sizeof(line) - n, "   ");
			if (i == 7 && n < (int)sizeof(line) - 2) line[n++] = ' ';
		}
		if (n < (int)sizeof(line) - 20)
		{
			line[n++] = ' ';
			line[n++] = '|';
			for (size_t i = 0; i < 16 && off + i < shown; i++)
			{
				unsigned char c = p[off + i];
				line[n++] = (c >= 32 && c < 127) ? (char)c : '.';
			}
		}
		line[n] = 0;
		printf("%s\n", line);
		util::Log("%s\n", line);
	}
	if (truncated)
	{
		printf("%s... (%u more bytes)\n", tag ? tag : "", (unsigned int)(len - shown));
		util::Log("%s... (%u more bytes)\n", tag ? tag : "", (unsigned int)(len - shown));
	}
}

bool util::LooksLikeSecretKey(const void* data, size_t len)
{
	const unsigned char* p = (const unsigned char*)data;
	for (size_t i = 0; i + 33 <= len; i++)
	{
		if (p[i] == 'A' && p[i + 1] == '3' && p[i + 2] == '-')
		{
			size_t j = i + 3, run = 0;
			while (j < len &&
				((p[j] >= 'A' && p[j] <= 'Z') || (p[j] >= '0' && p[j] <= '9') || p[j] == '-'))
			{
				j++; run++;
			}
			if (run >= 30)
				return true;
		}
	}
	return false;
}
