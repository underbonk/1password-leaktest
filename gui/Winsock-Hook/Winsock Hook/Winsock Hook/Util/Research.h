#pragma once

#include <winsock2.h>
#include <windows.h>

// Research layer: build-specific hooks inside 1Password's index.node.
// Layer model shown in the GUI:
//   [L1 SESSION-BODY]  request body before/after session encryption
//                      (what the 1Password server can ultimately read)
//   [L2 HTTP/2]        HTTP/2 frames before TLS (from the native writers)
//   [L3 TLS-OUT/IN]    TLS records at the Winsock boundary (what leaves the machine)

extern bool bLogResearch;  // F4 toggles L1+L2 display
extern bool bKeyWatch;     // F5 toggles the secret-key-shape watcher

// Creates the L1/L2 hooks if index.node is loaded and entry signatures match
// build 8.12.46.29 (SHA-256 3ddfb31d...). Call before MH_EnableHook.
// Returns true if the research layer is active.
bool InstallResearchHooks();
