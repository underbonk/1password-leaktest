#pragma once

#include <stddef.h>

namespace util
{
	void CreateConsole();
	HMODULE GetCurrentModule();
	void Log(const char *fmt, ...);
	// Hex-editor style dump (offset | hex | ASCII). Prints to console and log
	// file. maxConsole limits console output only; the log gets the same lines.
	void HexDump(const char* tag, const void* data, size_t len, size_t maxConsole);
	// Loose check for a formatted "A3-..." style key shape in a buffer.
	bool LooksLikeSecretKey(const void* data, size_t len);
}
