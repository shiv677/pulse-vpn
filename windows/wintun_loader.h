// Pulse VPN - Windows Wintun Driver Loader
// windows/wintun_loader.h

#pragma once

#include <windows.h>
#include <stdint.h>

typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;

typedef WINTUN_ADAPTER_HANDLE(WINAPI* WINTUN_CREATE_ADAPTER_FUNC)(
    LPCWSTR Name,
    LPCWSTR TunnelType,
    const GUID* RequestedGUID);
typedef WINTUN_ADAPTER_HANDLE(WINAPI* WINTUN_OPEN_ADAPTER_FUNC)(LPCWSTR Name);
typedef void(WINAPI* WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef WINTUN_SESSION_HANDLE(WINAPI* WINTUN_START_SESSION_FUNC)(
    WINTUN_ADAPTER_HANDLE Adapter,
    DWORD Capacity);
typedef void(WINAPI* WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef BYTE*(WINAPI* WINTUN_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    DWORD* PacketSize);
typedef void(WINAPI* WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    const BYTE* Packet);
typedef BYTE*(WINAPI* WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    DWORD PacketSize);
typedef void(WINAPI* WINTUN_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session,
    const BYTE* Packet);

class WintunDriverLoader {
public:
    WintunDriverLoader();
    ~WintunDriverLoader();

    bool InitializeDriver();
    bool CreatePulseAdapter(const wchar_t* adapterName = L"PulseVPN");
    bool StartTunnelSession(DWORD ringCapacity = 0x400000);
    void StopTunnelSession();

    bool IsLoaded() const { return wintunModule_ != nullptr; }

private:
    HMODULE wintunModule_ = nullptr;
    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;

    WINTUN_CREATE_ADAPTER_FUNC CreateAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC OpenAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC CloseAdapter = nullptr;
    WINTUN_START_SESSION_FUNC StartSession = nullptr;
    WINTUN_END_SESSION_FUNC EndSession = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC ReceivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC ReleaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC AllocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC SendPacket = nullptr;
};
