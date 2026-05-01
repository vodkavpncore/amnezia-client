/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Minimal WinDivert 2.x ABI shim.
// Mirrors the layout of WINDIVERT_ADDRESS and the prototypes of the
// few entry points we use, so we can dynamically load WinDivert.dll
// at runtime without depending on the upstream SDK headers at build time.
//
// Layout must stay binary-compatible with WinDivert 2.2.x.

#ifndef WINDIVERT_SHIM_H
#define WINDIVERT_SHIM_H

// winsock2.h before windows.h — see bypassrouter_win.h for rationale.
#include <winsock2.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Layer
#define WINDIVERT_LAYER_NETWORK         0
#define WINDIVERT_LAYER_NETWORK_FORWARD 1

// Open flags
#define WINDIVERT_FLAG_SNIFF        0x0001
#define WINDIVERT_FLAG_DROP         0x0002
#define WINDIVERT_FLAG_RECV_ONLY    0x0004
#define WINDIVERT_FLAG_SEND_ONLY    0x0008
#define WINDIVERT_FLAG_NO_INSTALL   0x0010
#define WINDIVERT_FLAG_FRAGMENTS    0x0020

// Shutdown directions
#define WINDIVERT_SHUTDOWN_RECV     0x1
#define WINDIVERT_SHUTDOWN_SEND     0x2
#define WINDIVERT_SHUTDOWN_BOTH     0x3

// Network-layer per-packet metadata
typedef struct {
  UINT32 IfIdx;
  UINT32 SubIfIdx;
} WINDIVERT_DATA_NETWORK;

#pragma pack(push, 1)
typedef struct {
  INT64  Timestamp;
  UINT32 Layer       : 8;
  UINT32 Event       : 8;
  UINT32 Sniffed     : 1;
  UINT32 Outbound    : 1;
  UINT32 Loopback    : 1;
  UINT32 Impostor    : 1;
  UINT32 IPv6        : 1;
  UINT32 IPChecksum  : 1;
  UINT32 TCPChecksum : 1;
  UINT32 UDPChecksum : 1;
  UINT32 Reserved1   : 8;
  UINT32 Reserved2;
  union {
    WINDIVERT_DATA_NETWORK Network;
    UINT8                  _reserved[64];
  };
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;
#pragma pack(pop)

static_assert(sizeof(WINDIVERT_ADDRESS) == 80,
              "WINDIVERT_ADDRESS must be 80 bytes (WinDivert 2.x ABI)");

// Function pointer typedefs (matching WinDivert 2.x exports)
typedef HANDLE(WINAPI* PFN_WinDivertOpen)(const char* filter, UINT layer,
                                          INT16 priority, UINT64 flags);
typedef BOOL(WINAPI* PFN_WinDivertRecv)(HANDLE handle, VOID* pPacket,
                                        UINT packetLen, UINT* pRecvLen,
                                        WINDIVERT_ADDRESS* pAddr);
typedef BOOL(WINAPI* PFN_WinDivertSend)(HANDLE handle, const VOID* pPacket,
                                        UINT packetLen, UINT* pSendLen,
                                        const WINDIVERT_ADDRESS* pAddr);
typedef BOOL(WINAPI* PFN_WinDivertShutdown)(HANDLE handle, UINT how);
typedef BOOL(WINAPI* PFN_WinDivertClose)(HANDLE handle);
typedef UINT(WINAPI* PFN_WinDivertHelperCalcChecksums)(VOID* pPacket,
                                                      UINT packetLen,
                                                      WINDIVERT_ADDRESS* pAddr,
                                                      UINT64 flags);

#ifdef __cplusplus
}
#endif

#endif  // WINDIVERT_SHIM_H
